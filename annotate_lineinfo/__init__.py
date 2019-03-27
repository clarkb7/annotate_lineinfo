from .annotate_lineinfo import DIASession

try:
    import idaapi
except ImportError:
    pass
else:
    from .annotate_lineinfo import ida_annotate_lineinfo
