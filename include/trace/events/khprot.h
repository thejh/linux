#undef TRACE_SYSTEM
#define TRACE_SYSTEM khprot

#if !defined(_TRACE_KHP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KHP_H

#include <linux/tracepoint.h>

#ifdef CONFIG_KHP_DEBUG
#include <linux/slub_def.h>
TRACE_EVENT(globalize,
	TP_PROTO(int old_cpu, int new_cpu, struct kmem_cache *slab),
	TP_ARGS(old_cpu, new_cpu, slab),
	TP_STRUCT__entry(
		__field(	int,	old_cpu			)
		__field(	int,	new_cpu			)
		__array(	char,	slab_name, 32)
	),
	TP_fast_assign(
		__entry->old_cpu = old_cpu;
		__entry->new_cpu = new_cpu;
		strlcpy(__entry->slab_name, slab->name,
			sizeof(__entry->slab_name));
	),
	TP_printk("old_cpu=%d new_cpu=%d slab=%s",
		__entry->old_cpu, __entry->new_cpu, __entry->slab_name)
);
#endif /* CONFIG_KHP_DEBUG */

#endif /* _TRACE_KHP_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
