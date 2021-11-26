#include "rwlock.h"
#include <errno.h>

#define atomic_xadd(P, V) __sync_fetch_and_add((P), (V))
#define cmpxchg(P, O, N) __sync_val_compare_and_swap((P), (O), (N))
#define atomic_inc(P) __sync_add_and_fetch((P), 1)
#define atomic_add(P, V) __sync_add_and_fetch((P), (V))
#define atomic_set_bit(P, V) __sync_or_and_fetch((P), 1<<(V))

/* Compile read-write barrier */
#define barrier() __asm__ volatile("": : :"memory")

/* Pause instruction to prevent excess processor bus usage */
#define cpu_relax() __asm__ volatile("pause": : :"memory")

#define RW_WAIT_BIT		0
#define RW_WRITE_BIT	1
#define RW_READ_BIT		2

#define RW_WAIT		1
#define RW_WRITE	2
#define RW_READ		4

/* Test and set a bit */
static inline char atomic_bitsetandtest(void *ptr, int x)
{
	char out;
	__asm__ __volatile__("lock; bts %2,%1\n"
	                     "sbb %0,%0\n"
	:"=r" (out), "=m" (*(volatile long long *)ptr)
	:"Ir" (x)
	:"memory");

	return out;
}

void none_unlock(rwlock_t *l)
{
	// do nothing
}

void write_lock(rwlock_t *l)
{
	while (1)
	{
		unsigned state = *l;

		/* No readers or writers? */
		if (state < RW_WRITE)
		{
			/* Turn off RW_WAIT, and turn on RW_WRITE */
			if (cmpxchg(l, state, RW_WRITE) == state) return;

			/* Someone else got there... time to wait */
			state = *l;
		}

		/* Turn on writer wait bit */
		if (!(state & RW_WAIT)) atomic_set_bit(l, RW_WAIT_BIT);

		/* Wait until can try to take the lock */
		while (*l > RW_WAIT) cpu_relax();
	}
}

void write_unlock(rwlock_t *l)
{
	atomic_add(l, -RW_WRITE);
}

int write_trylock(rwlock_t *l)
{
	unsigned state = *l;

	if ((state < RW_WRITE) && (cmpxchg(l, state, state + RW_WRITE) == state)) return 0;

	return EBUSY;
}

void read_lock(rwlock_t *l)
{
	while (1)
	{
		/* A writer exists? */
		while (*l & (RW_WAIT | RW_WRITE)) cpu_relax();

		/* Try to get read lock */
		if (!(atomic_xadd(l, RW_READ) & (RW_WAIT | RW_WRITE))) return;

		/* Undo */
		atomic_add(l, -RW_READ);
	}
}

void read_unlock(rwlock_t *l)
{
	atomic_add(l, -RW_READ);
}

int read_trylock(rwlock_t *l)
{
	/* Try to get read lock */
	unsigned state = atomic_xadd(l, RW_READ);

	if (!(state & (RW_WAIT | RW_WRITE))) return 0;

	/* Undo */
	atomic_add(l, -RW_READ);

	return EBUSY;
}

int upgrade_trylock(rwlock_t *l)
{
	/* Someone else is trying (and will succeed) to upgrade to a write lock? */
	if (atomic_bitsetandtest(l, RW_WRITE_BIT)) return EBUSY;

	/* Don't count myself any more */
	atomic_add(l, -RW_READ);

	/* Wait until there are no more readers */
	while (*l > (RW_WAIT | RW_WRITE)) cpu_relax();

	return 0;
}

void upgrade_lock(rwlock_t *l)
{
	while(upgrade_trylock(l) != 0)
	{
		// Someone else is trying to upgrade
		cpu_relax();
	}
}
