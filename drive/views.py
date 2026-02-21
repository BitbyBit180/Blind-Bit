"""
Drive views — File management, search, records, visualizer.
All data operations require 2FA verification (keys derived from password + TOTP).
"""
import os
import json
import time
import tempfile
import base64
import logging
import re

from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST
from django.db.models import Count, Sum
from django.contrib import messages
from django.utils.encoding import escape_uri_path

from accounts.models import UserProfile
from .models import EncryptedFile, FileIndex, EncryptedRecord, RecordIndex, SearchHistory
from .sse_bridge import (
    derive_keys, encrypt_file_data, decrypt_file_data,
    build_index, generate_tokens_for_search, visualize_encryption,
    preprocess, extract_text, encrypt_record, decrypt_record,
    build_record_index, find_fuzzy_keywords,
    regex_to_search_fragments, verify_regex_match,
)

logger = logging.getLogger(__name__)


def _get_keys(request):
    """Get user's derived keys from session.

    Reads the DEK (Data Encryption Key) stored in session['_dek'] and
    expands it into the three purpose-specific sub-keys via HKDF.
    Returns None if the vault is locked or the user is not authenticated.
    """
    dek_b64 = request.session.get('_dek')  # was '_mk' pre-DEK upgrade
    if not dek_b64:
        return None
    try:
        dek = base64.b64decode(dek_b64)
        return derive_keys(dek)
    except Exception:
        return None


def _get_counter(request):
    ctr = request.session.get('_counter', 0) + 1
    request.session['_counter'] = ctr
    return ctr


def _run_decoy_lookups(user):
    """Run no-op decoy lookups to reduce direct query-pattern observability."""
    if not getattr(settings, 'SEARCH_OBFUSCATION_ENABLED', False):
        return
    decoys = max(0, int(getattr(settings, 'SEARCH_OBFUSCATION_DECOYS', 0)))
    for _ in range(decoys):
        decoy = os.urandom(16).hex()
        list(FileIndex.objects.filter(file__owner=user, token=decoy).values_list('id', flat=True)[:1])
        list(RecordIndex.objects.filter(record__owner=user, token=decoy).values_list('id', flat=True)[:1])


@login_required
def dashboard(request):
    profile = UserProfile.objects.get_or_create(user=request.user)[0]

    file_count = EncryptedFile.objects.filter(owner=request.user).count()
    record_count = EncryptedRecord.objects.filter(owner=request.user).count()
    k_tokens = FileIndex.objects.filter(file__owner=request.user, token_type='K').count()
    n_tokens = FileIndex.objects.filter(file__owner=request.user, token_type='N').count()
    b_tokens = FileIndex.objects.filter(file__owner=request.user, token_type='B').count()
    total_tokens = k_tokens + n_tokens + b_tokens
    r_tokens = RecordIndex.objects.filter(record__owner=request.user).count()
    recent_searches = SearchHistory.objects.filter(user=request.user)[:5]
    total_items = file_count + record_count

    indexed_file_count = FileIndex.objects.filter(
        file__owner=request.user
    ).values('file__file_id').distinct().count()
    indexed_record_count = RecordIndex.objects.filter(
        record__owner=request.user
    ).values('record__record_id').distinct().count()
    indexed_items = indexed_file_count + indexed_record_count

    if not profile.is_2fa_enabled or total_items == 0:
        search_state = 'disabled'
    elif indexed_items < total_items:
        search_state = 'partial'
    else:
        search_state = 'full'

    if total_items == 0:
        status_state = 'empty'
        status_tone = 'yellow'
        status_message = 'No protected data yet'
    elif indexed_items < total_items:
        status_state = 'attention'
        status_tone = 'red'
        status_message = 'Search index out of sync'
    else:
        status_state = 'healthy'
        status_tone = 'green'
        status_message = 'All records encrypted and searchable'

    latest_file = EncryptedFile.objects.filter(owner=request.user).order_by('-uploaded_at').first()
    latest_record = EncryptedRecord.objects.filter(owner=request.user).order_by('-uploaded_at').first()
    latest_encryption_activity = None
    if latest_file and latest_record:
        latest_encryption_activity = max(latest_file.uploaded_at, latest_record.uploaded_at)
    elif latest_file:
        latest_encryption_activity = latest_file.uploaded_at
    elif latest_record:
        latest_encryption_activity = latest_record.uploaded_at

    recovery_codes_remaining = 0
    try:
        recovery_codes_remaining = len(json.loads(profile.recovery_code_hashes or '[]'))
    except Exception:
        recovery_codes_remaining = 0

    user_agent = (request.META.get('HTTP_USER_AGENT') or '').strip()
    if not user_agent:
        last_login_device = 'Unknown device'
    elif len(user_agent) > 70:
        last_login_device = f"{user_agent[:67]}..."
    else:
        last_login_device = user_agent

    return render(request, 'drive/dashboard.html', {
        'file_count': file_count,
        'record_count': record_count,
        'k_tokens': k_tokens,
        'n_tokens': n_tokens,
        'b_tokens': b_tokens,
        'total_tokens': total_tokens,
        'r_tokens': r_tokens,
        'recent_searches': recent_searches,
        'is_2fa_enabled': profile.is_2fa_enabled,
        'status_state': status_state,
        'status_tone': status_tone,
        'status_message': status_message,
        'search_state': search_state,
        'latest_encryption_activity': latest_encryption_activity,
        'last_login_device': last_login_device,
        'key_age_days': int(max(0, (time.time() - request.user.date_joined.timestamp()) // 86400)),
        'recovery_codes_remaining': recovery_codes_remaining,
        'has_recovery_codes': recovery_codes_remaining > 0,
        'needs_rebuild_index': total_items > 0 and indexed_items < total_items,
    })


@login_required
def files_view(request):
    files = EncryptedFile.objects.filter(owner=request.user)
    records = EncryptedRecord.objects.filter(owner=request.user)
    return render(request, 'drive/files.html', {'files': files, 'records': records})


@login_required
def upload_page(request):
    return render(request, 'drive/upload.html')


@login_required
@require_POST
def upload_file(request):
    keys = _get_keys(request)
    if not keys:
        return JsonResponse({'error': '2FA required'}, status=403)

    uploaded = request.FILES.get('file')
    if not uploaded:
        return JsonResponse({'error': 'No file selected'}, status=400)
    manual_keyword_input = (request.POST.get('manual_keyword') or '').strip()

    ext = os.path.splitext(uploaded.name)[1].lower()
    if ext not in ('.pdf', '.txt'):
        return JsonResponse({'error': 'Only PDF/TXT files supported'}, status=400)

    # Save to temp file for processing
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        for chunk in uploaded.chunks():
            tmp.write(chunk)
        tmp_path = tmp.name

    try:
        t0 = time.perf_counter()

        # Extract text and preprocess
        raw_text = extract_text(tmp_path)
        keywords = preprocess(raw_text)

        manual_keywords = []
        if manual_keyword_input:
            # Accept comma-separated values: "alpha, beta key, gamma"
            for part in manual_keyword_input.split(','):
                part = part.strip()
                if part:
                    manual_keywords.extend(preprocess(part))

        added_manual_keywords = []
        if manual_keywords:
            seen = set(keywords)
            for kw in manual_keywords:
                if kw not in seen:
                    keywords.append(kw)
                    seen.add(kw)
                    added_manual_keywords.append(kw)

        if not keywords:
            return JsonResponse({'error': 'No searchable content found'}, status=400)

        # Encrypt file
        file_id, enc_data, enc_time = encrypt_file_data(tmp_path, keys['file_encryption_key'])

        # Build index
        counter = _get_counter(request)
        index_entries, idx_time, tfidf = build_index(
            keywords, file_id, keys['hmac_key'],
            keys['token_randomization_key'], counter, raw_text=raw_text
        )

        # Store in DB
        ef = EncryptedFile.objects.create(
            file_id=file_id, filename=uploaded.name,
            encrypted_data=enc_data, owner=request.user
        )
        for token, fid, ttype, score in index_entries:
            FileIndex.objects.create(file=ef, token=token, token_type=ttype, score=score)

        k = sum(1 for e in index_entries if e[2] == 'K')
        n = sum(1 for e in index_entries if e[2] == 'N')
        b = sum(1 for e in index_entries if e[2] == 'B')
        top_tfidf = sorted(tfidf.items(), key=lambda x: x[1], reverse=True)[:5]
        total_time = time.perf_counter() - t0

        return JsonResponse({
            'success': True,
            'file_id': file_id,
            'filename': uploaded.name,
            'keywords': len(keywords),
            'secret_keywords_added': added_manual_keywords,
            'tokens': {'total': len(index_entries), 'K': k, 'N': n, 'B': b},
            'tfidf_top': [{'keyword': kw, 'score': round(sc, 4)} for kw, sc in top_tfidf],
            'encrypt_time': round(enc_time, 4),
            'index_time': round(idx_time, 4),
            'total_time': round(total_time, 4),
            'size': len(enc_data),
        })
    finally:
        os.unlink(tmp_path)


@login_required
def search_view(request):
    return render(request, 'drive/search.html')


def parse_query(query):
    """Parse query into required (+), optional (plain), and excluded (-) terms."""
    required, optional, excluded = [], [], []
    for token in query.strip().split():
        if token.startswith('-') and len(token) > 1:
            excluded.append(token[1:])
        elif token.startswith('+') and len(token) > 1:
            required.append(token[1:])
        else:
            optional.append(token)
    return required, optional, excluded


def _query_terms_for_preview(query: str):
    """Extract searchable terms from query for preview snippet selection."""
    # Prioritize the same normalized terms used by index/search tokenization.
    primary = preprocess(query)
    terms = [t.lower() for t in primary if t]
    seen = set(terms)
    # Add a fallback pass so unusual symbols/short forms can still be considered.
    for raw in query.split():
        token = raw.strip()
        if not token:
            continue
        if token.startswith('+') or token.startswith('-'):
            token = token[1:]
        token = token.strip('"').replace('*', '')
        token = re.sub(r'[^\w-]', '', token, flags=re.UNICODE)
        token = token.lower()
        if len(token) >= 2 and token not in seen:
            terms.append(token)
            seen.add(token)
    return terms


def _preview_around_match(full_text: str, terms, width: int | None = 400) -> str:
    """Return a preview centered around the first query-term match."""
    if not full_text:
        return ''
    if width is None or width <= 0:
        return full_text
    if not terms:
        return full_text[:width]

    lower_text = full_text.lower()
    first_idx = -1
    match_len = 0
    for term in terms:
        idx = lower_text.find(term)
        if idx != -1 and (first_idx == -1 or idx < first_idx):
            first_idx = idx
            match_len = len(term)

    if first_idx == -1:
        return full_text[:width]

    half = width // 2
    start = max(0, first_idx - half)
    end = min(len(full_text), first_idx + match_len + half)
    snippet = full_text[start:end]
    if start > 0:
        snippet = '... ' + snippet
    if end < len(full_text):
        snippet = snippet + ' ...'
    return snippet


@login_required
@require_POST
def search_api(request):
    keys = _get_keys(request)
    if not keys:
        return JsonResponse({'error': '2FA required'}, status=403)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
    query = data.get('query', '').strip()
    search_mode = data.get('mode', 'exact')
    logic = data.get('logic', 'AND')  # Default logic for optional terms

    if not query:
        return JsonResponse({'error': 'Empty query'}, status=400)
    if logic not in ('AND', 'OR'):
        return JsonResponse({'error': 'Invalid logic mode'}, status=400)
    if search_mode not in ('exact', 'substring', 'phrase', 'wildcard', 'fuzzy', 'regex'):
        return JsonResponse({'error': 'Invalid search mode'}, status=400)

    req_terms, opt_terms, neg_terms = parse_query(query)
    preview_terms = _query_terms_for_preview(query)

    t0 = time.perf_counter()

    # 2. Token Generation Strategy
    counter = request.session.get('_counter', 0)
    req_tok_lists = []
    opt_tok_lists = []

    if search_mode == 'fuzzy':
        # Fuzzy Logic: (Term1 OR variants) AND (Term2 OR variants) ...
        # Each term becomes a constraint group of original + close variants.
        all_kw = set()
        # Optimization: cache keywords? For now loading from DB is fine for prototype
        for r in EncryptedRecord.objects.filter(owner=request.user):
            try:
                all_kw.update(json.loads(r.keywords_json))
            except:
                pass

        def _build_fuzzy_groups(terms):
            groups = []
            for term in terms:
                variants = find_fuzzy_keywords(term, list(all_kw), max_distance=2)
                group_tokens = []
                forms = set([term] + variants)

                for form in forms:
                    tls, _ = generate_tokens_for_search(
                        form, keys['hmac_key'], keys['token_randomization_key'],
                        counter, 'exact'
                    )
                    if tls:
                        group_tokens.extend(tls[0])

                if group_tokens:
                    groups.append(group_tokens)
            return groups

        req_tok_lists = _build_fuzzy_groups(req_terms)
        opt_tok_lists = _build_fuzzy_groups(opt_terms)

    else:
        # Standard Logic (Exact, Substring, Phrase, Wildcard)
        # Build required and optional groups separately so +term is always enforced.
        req_query_str = " ".join(req_terms)
        opt_query_str = " ".join(opt_terms)
        if req_query_str:
            req_tok_lists, _ = generate_tokens_for_search(
                req_query_str, keys['hmac_key'], keys['token_randomization_key'],
                counter, search_mode
            )
        if opt_query_str:
            opt_tok_lists, _ = generate_tokens_for_search(
                opt_query_str, keys['hmac_key'], keys['token_randomization_key'],
                counter, search_mode
            )

    # Negative Tokens
    neg_query_str = " ".join(neg_terms)
    neg_tok_lists, _ = generate_tokens_for_search(
        neg_query_str, keys['hmac_key'], keys['token_randomization_key'],
        counter, search_mode if search_mode != 'fuzzy' else 'exact'
    )

    if not req_tok_lists and not opt_tok_lists and not neg_tok_lists:
        return JsonResponse({
            'results': [], 'file_results': [], 'record_results': [],
            'search_time': 0, 'regex_info': None
        })

    _run_decoy_lookups(request.user)

    # 4. Search & Set Logic (Files)
    # ---------------------------
    
    # A. Positives
    def _group_match_file_ids(token_groups):
        if not token_groups:
            return set()
        ids = set(FileIndex.objects.filter(
            file__owner=request.user, token__in=token_groups[0]
        ).values_list('file__file_id', flat=True))
        for tokens in token_groups[1:]:
            if not ids:
                break
            next_ids = set(FileIndex.objects.filter(
                file__owner=request.user, token__in=tokens
            ).values_list('file__file_id', flat=True))
            ids &= next_ids
        return ids

    req_file_ids = _group_match_file_ids(req_tok_lists) if req_tok_lists else None
    opt_file_ids = set()
    if opt_tok_lists:
        if logic == 'AND':
            opt_file_ids = _group_match_file_ids(opt_tok_lists)
        else:
            all_opt_tokens = [t for tl in opt_tok_lists for t in tl]
            opt_file_ids = set(FileIndex.objects.filter(
                file__owner=request.user, token__in=all_opt_tokens
            ).values_list('file__file_id', flat=True))

    if req_file_ids is None:
        candidate_file_ids = opt_file_ids
    elif logic == 'AND' and opt_tok_lists:
        candidate_file_ids = req_file_ids & opt_file_ids
    else:
        candidate_file_ids = req_file_ids

    # B. Negatives (Exclude)
    if neg_tok_lists:
        all_neg_tokens = [t for tl in neg_tok_lists for t in tl]
        exclude_file_ids = set(FileIndex.objects.filter(
             file__owner=request.user, token__in=all_neg_tokens
        ).values_list('file__file_id', flat=True))
        candidate_file_ids -= exclude_file_ids

    # C. Ranking & Fetching (Files)
    file_results = []
    regex_file_matches = {}
    
    if candidate_file_ids:
        # Sum scores for RELEVANT tokens (positives) only
        all_pos_tokens = [t for tl in (req_tok_lists + opt_tok_lists) for t in tl]
        
        file_hits = FileIndex.objects.filter(
            file__file_id__in=candidate_file_ids,
            token__in=all_pos_tokens
        ).values('file__file_id', 'file__filename').annotate(
            total_score=Sum('score'), 
            match_count=Count('token', distinct=True)
        ).order_by('-total_score')

        for hit in file_hits:
            fid = hit['file__file_id']
            fname = hit['file__filename']
            score = hit['total_score'] or 0

            # Decrypt preview
            try:
                ef = EncryptedFile.objects.get(file_id=fid)
                plain = decrypt_file_data(bytes(ef.encrypted_data), fid, keys['file_encryption_key'])
                ext = os.path.splitext(fname or '')[1].lower()
                if ext == '.pdf':
                    tmp_pdf_path = None
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_pdf:
                            tmp_pdf.write(plain)
                            tmp_pdf_path = tmp_pdf.name
                        full_text = extract_text(tmp_pdf_path)
                    finally:
                        if tmp_pdf_path and os.path.exists(tmp_pdf_path):
                            os.unlink(tmp_pdf_path)
                else:
                    full_text = plain.decode('utf-8', errors='replace')
                preview = _preview_around_match(full_text, preview_terms, width=None)
            except:
                full_text = ''
                preview = '[decrypt error]'

            # Regex Phase 2
            regex_matches = []
            if search_mode == 'regex' and full_text:
                try:
                    analysis = regex_to_search_fragments(query)
                    matches = verify_regex_match(analysis['compiled'], full_text)
                    if not matches: continue
                    regex_matches = [{'match': m['match'], 'context': m['context']} for m in matches[:5]]
                    regex_file_matches[fid] = regex_matches
                except:
                    pass

            file_results.append({
                'type': 'file',
                'id': fid,
                'name': fname,
                'preview': preview,
                'score': round(score, 4),
                'match_count': hit['match_count'],
                'regex_matches': regex_matches,
            })

    # 5. Search & Set Logic (Records)
    # -----------------------------
    # Similar logic for records
    
    # A. Positives
    def _group_match_record_ids(token_groups):
        if not token_groups:
            return set()
        ids = set(RecordIndex.objects.filter(
            record__owner=request.user, token__in=token_groups[0]
        ).values_list('record__record_id', flat=True))
        for tokens in token_groups[1:]:
            if not ids:
                break
            next_ids = set(RecordIndex.objects.filter(
                record__owner=request.user, token__in=tokens
            ).values_list('record__record_id', flat=True))
            ids &= next_ids
        return ids

    req_rec_ids = _group_match_record_ids(req_tok_lists) if req_tok_lists else None
    opt_rec_ids = set()
    if opt_tok_lists:
        if logic == 'AND':
            opt_rec_ids = _group_match_record_ids(opt_tok_lists)
        else:
            all_opt_tokens = [t for tl in opt_tok_lists for t in tl]
            opt_rec_ids = set(RecordIndex.objects.filter(
                record__owner=request.user, token__in=all_opt_tokens
            ).values_list('record__record_id', flat=True))

    if req_rec_ids is None:
        candidate_rec_ids = opt_rec_ids
    elif logic == 'AND' and opt_tok_lists:
        candidate_rec_ids = req_rec_ids & opt_rec_ids
    else:
        candidate_rec_ids = req_rec_ids

    # B. Negatives
    if neg_tok_lists:
        all_neg_tokens = [t for tl in neg_tok_lists for t in tl]
        exclude_rec_ids = set(RecordIndex.objects.filter(
             record__owner=request.user, token__in=all_neg_tokens
        ).values_list('record__record_id', flat=True))
        candidate_rec_ids -= exclude_rec_ids

    # C. Ranking (Records)
    record_results = []
    if candidate_rec_ids:
        all_pos_tokens = [t for tl in (req_tok_lists + opt_tok_lists) for t in tl]
        rec_hits = RecordIndex.objects.filter(
            record__record_id__in=candidate_rec_ids,
            token__in=all_pos_tokens
        ).values('record__record_id', 'record__record_type').annotate(
            total_score=Sum('score'), 
            match_count=Count('token', distinct=True)
        ).order_by('-total_score')

        for hit in rec_hits:
            rid = hit['record__record_id']
            try:
                rec = EncryptedRecord.objects.get(record_id=rid)
                plain = decrypt_record(bytes(rec.encrypted_data), keys['file_encryption_key'])
                preview = _preview_around_match(plain, preview_terms, width=None)
            except:
                preview = '[decrypt error]'

            record_results.append({
                'type': 'record',
                'id': rid,
                'record_type': hit['record__record_type'],
                'preview': preview,
                'score': round(hit['total_score'] or 0, 4),
                'match_count': hit['match_count'],
            })

    search_time = time.perf_counter() - t0

    # Regex info
    regex_info = None
    if search_mode == 'regex':
        try:
            analysis = regex_to_search_fragments(query)
            regex_info = {
                'fragments': [f['text'] for f in analysis['fragments']],
                'complexity': analysis['complexity'],
                'has_wildcards': analysis['has_wildcards'],
            }
        except:
            pass

    # Log analytics
    total_results = len(file_results) + len(record_results)
    all_tokens_count = sum(len(tl) for tl in req_tok_lists + opt_tok_lists + neg_tok_lists)
    
    SearchHistory.objects.create(
        user=request.user, search_type=search_mode, logic_mode=logic,
        token_count=all_tokens_count, result_count=total_results,
        duration_ms=search_time * 1000,
    )

    return JsonResponse({
        'file_results': file_results,
        'record_results': record_results,
        'total': total_results,
        'search_time': round(search_time, 4),
        'search_mode': search_mode,
        'regex_info': regex_info,
    })


@login_required
def download_file(request, file_id):
    keys = _get_keys(request)
    if not keys:
        messages.error(request, '2FA required to download files.')
        return redirect('files')

    ef = get_object_or_404(EncryptedFile, file_id=file_id, owner=request.user)
    try:
        plaintext = decrypt_file_data(bytes(ef.encrypted_data), file_id, keys['file_encryption_key'])
    except Exception as e:
        messages.error(request, f'Decryption failed: {e}')
        return redirect('files')

    response = HttpResponse(plaintext, content_type='application/octet-stream')
    # Fix header injection and ensure non-ascii filenames work
    response['Content-Disposition'] = f"attachment; filename*=UTF-8''{escape_uri_path(ef.filename)}"
    return response


@login_required
@require_POST
def delete_file(request, file_id):
    keys = _get_keys(request)
    if not keys:
        return JsonResponse({'error': '2FA required'}, status=403)
    ef = get_object_or_404(EncryptedFile, file_id=file_id, owner=request.user)
    ef.delete()
    return JsonResponse({'success': True})


@login_required
def records_view(request):
    records = EncryptedRecord.objects.filter(owner=request.user)
    return render(request, 'drive/records.html', {'records': records})


@login_required
@require_POST
def upload_record(request):
    keys = _get_keys(request)
    if not keys:
        return JsonResponse({'error': '2FA required'}, status=403)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    content = data.get('content', '').strip()
    record_type = data.get('type', 'text')

    if not content:
        return JsonResponse({'error': 'Empty content'}, status=400)

    if record_type == 'json':
        try:
            parsed = json.loads(content)
        except:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    else:
        parsed = content

    rid, enc_blob, rtype, enc_time = encrypt_record(parsed, keys['file_encryption_key'])
    counter = _get_counter(request)
    entries, idx_time, tfidf, keywords = build_record_index(
        parsed, rid, keys['hmac_key'], keys['token_randomization_key'], counter
    )

    rec = EncryptedRecord.objects.create(
        record_id=rid, record_type=rtype,
        encrypted_data=enc_blob,
        keywords_json=json.dumps(keywords),
        owner=request.user
    )
    for token, rid_ref, ttype, score in entries:
        RecordIndex.objects.create(record=rec, token=token, token_type=ttype, score=score)

    k = sum(1 for e in entries if e[2] == 'K')
    n = sum(1 for e in entries if e[2] == 'N')
    b = sum(1 for e in entries if e[2] == 'B')

    return JsonResponse({
        'success': True,
        'record_id': rec.record_id,
        'tokens': {'total': len(entries), 'K': k, 'N': n, 'B': b},
        'encrypt_time': round(enc_time, 4),
    })


@login_required
@require_POST
def delete_record(request, record_id):
    keys = _get_keys(request)
    if not keys:
        return JsonResponse({'error': '2FA required'}, status=403)
    rec = get_object_or_404(EncryptedRecord, record_id=record_id, owner=request.user)
    rec.delete()
    return JsonResponse({'success': True})


@login_required
def view_record(request, record_id):
    keys = _get_keys(request)
    if not keys:
        return JsonResponse({'error': '2FA required'}, status=403)
    rec = get_object_or_404(EncryptedRecord, record_id=record_id, owner=request.user)
    try:
        plain = decrypt_record(bytes(rec.encrypted_data), keys['file_encryption_key'])
        try:
            formatted = json.dumps(json.loads(plain), indent=2)
        except:
            formatted = plain
    except:
        formatted = '[Decryption failed]'
    return JsonResponse({'content': formatted, 'type': rec.record_type})


@login_required
def visualizer_view(request):
    return render(request, 'drive/visualizer.html')


@login_required
@require_POST
def visualizer_api(request):
    keys = _get_keys(request)
    if not keys:
        return JsonResponse({'error': '2FA required'}, status=403)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    text = data.get('text', '')
    if not text:
        return JsonResponse({'keywords': [], 'hmac_tokens': [], 'ngram_tokens': [],
                             'ciphertext_hex': '', 'plaintext_length': 0, 'ciphertext_length': 0})

    try:
        result = visualize_encryption(text, keys['hmac_key'], keys['token_randomization_key'], keys['file_encryption_key'])
        return JsonResponse(result)
    except Exception as e:
        logger.exception("Visualizer API failed for user_id=%s", request.user.id)
        return JsonResponse({'error': 'Server error while processing visualization.'}, status=500)


@login_required
def analytics_view(request):
    searches = SearchHistory.objects.filter(user=request.user)[:30]
    return render(request, 'drive/analytics.html', {'searches': searches})
