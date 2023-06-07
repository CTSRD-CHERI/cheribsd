/* Public domain. */

struct dma_fence_chain {
        struct dma_fence base;
        spinlock_t lock;
        struct dma_fence __rcu *prev;
        u64 prev_seqno;
        struct dma_fence *fence;
        struct dma_fence_cb cb;
#ifdef __linux__
        struct irq_work work;
#endif
};

extern const struct dma_fence_ops dma_fence_chain_ops;

static inline struct dma_fence_chain *
to_dma_fence_chain(struct dma_fence *fence)
{
        if (!fence || fence->ops != &dma_fence_chain_ops)
                return NULL;

        return container_of(fence, struct dma_fence_chain, base);
}

#define dma_fence_chain_for_each(iter, head)   \
        for (iter = dma_fence_get(head); iter; \
             iter = dma_fence_chain_walk(iter))
struct dma_fence *dma_fence_chain_walk(struct dma_fence *fence);
int dma_fence_chain_find_seqno(struct dma_fence **pfence, uint64_t seqno);

void dma_fence_chain_init(struct dma_fence_chain *chain,
                          struct dma_fence *prev,
                          struct dma_fence *fence,
                          uint64_t seqno);
