"""
tests/unit/test_registry.py — Tests for the registry system.
"""

import pytest
from corvida.core.registry import Registry


class TestRegistry:
    def test_register_and_retrieve(self) -> None:
        r = Registry()

        class Foo:
            name = "foo"

        r.register(Foo)
        assert r["foo"] is Foo

    def test_duplicate_raises(self) -> None:
        r = Registry()

        class Foo:
            name = "foo"

        r.register(Foo)
        with pytest.raises(ValueError, match="Duplicate"):
            r.register(Foo)

    def test_all_returns_list(self) -> None:
        r = Registry()

        class A:
            name = "a"

        class B:
            name = "b"

        r.register(A)
        r.register(B)
        assert set(r.all()) == {A, B}

    def test_get_or_raise_missing(self) -> None:
        r = Registry()
        with pytest.raises(KeyError, match="not found"):
            r.get_or_raise("nonexistent")

    def test_decorator_usage(self) -> None:
        r = Registry()

        @r.register
        class Bar:
            name = "bar"

        assert r["bar"] is Bar
