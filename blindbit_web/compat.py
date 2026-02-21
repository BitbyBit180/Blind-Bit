"""
Runtime compatibility fixes for known upstream issues.
"""

from __future__ import annotations

from copy import copy


def patch_django_template_context_copy() -> bool:
    """
    Patch Django's BaseContext.__copy__ for Python 3.14 compatibility.

    Django 5.1.x uses copy(super()) inside BaseContext.__copy__, which raises:
    AttributeError: 'super' object has no attribute 'dicts'
    on Python 3.14.
    """
    from django.template.context import BaseContext, Context

    try:
        copy(Context({}))
        return False
    except AttributeError:
        pass

    def _base_context_copy(self):
        duplicate = self.__class__.__new__(self.__class__)
        duplicate.__dict__ = self.__dict__.copy()
        duplicate.dicts = self.dicts[:]
        return duplicate

    BaseContext.__copy__ = _base_context_copy
    return True
