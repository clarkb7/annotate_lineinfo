from .annotate_lineinfo import dia_iter_lineinfo

try:
    import idaapi
except ImportError:
    pass
else:
    from .annotate_lineinfo import ida_annotate_lineinfo
