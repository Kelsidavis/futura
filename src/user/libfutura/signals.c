#include <user/signal.h>
#include <stddef.h>
#include <stdint.h>

static inline size_t sigset_word_count(void) {
    return sizeof(sigset_t) / sizeof(unsigned long);
}

static inline unsigned long *sigset_words(sigset_t *set) {
    return (unsigned long *)set;
}

static inline const unsigned long *sigset_cwords(const sigset_t *set) {
    return (const unsigned long *)set;
}

static inline int valid_signal(int signum) {
    if (signum <= 0) {
        return 0;
    }
    size_t total_bits = sizeof(sigset_t) * 8u;
    return (size_t)(signum - 1) < total_bits;
}

int sigemptyset(sigset_t *set) {
    if (!set) {
        return -1;
    }
    unsigned long *words = sigset_words(set);
    for (size_t i = 0; i < sigset_word_count(); ++i) {
        words[i] = 0;
    }
    return 0;
}

int sigfillset(sigset_t *set) {
    if (!set) {
        return -1;
    }
    unsigned long *words = sigset_words(set);
    for (size_t i = 0; i < sigset_word_count(); ++i) {
        words[i] = ~0UL;
    }
    return 0;
}

int sigaddset(sigset_t *set, int signum) {
    if (!set || !valid_signal(signum)) {
        return -1;
    }
    unsigned long *words = sigset_words(set);
    size_t idx = (size_t)(signum - 1) / (sizeof(unsigned long) * 8u);
    size_t bit = (size_t)(signum - 1) % (sizeof(unsigned long) * 8u);
    words[idx] |= (1UL << bit);
    return 0;
}

int sigdelset(sigset_t *set, int signum) {
    if (!set || !valid_signal(signum)) {
        return -1;
    }
    unsigned long *words = sigset_words(set);
    size_t idx = (size_t)(signum - 1) / (sizeof(unsigned long) * 8u);
    size_t bit = (size_t)(signum - 1) % (sizeof(unsigned long) * 8u);
    words[idx] &= ~(1UL << bit);
    return 0;
}

int sigismember(const sigset_t *set, int signum) {
    if (!set || !valid_signal(signum)) {
        return 0;
    }
    const unsigned long *words = sigset_cwords(set);
    size_t idx = (size_t)(signum - 1) / (sizeof(unsigned long) * 8u);
    size_t bit = (size_t)(signum - 1) % (sizeof(unsigned long) * 8u);
    return (words[idx] >> bit) & 1UL;
}

static sigset_t current_mask;
static int mask_initialised = 0;

static void ensure_mask_initialised(void) {
    if (!mask_initialised) {
        sigemptyset(&current_mask);
        mask_initialised = 1;
    }
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    ensure_mask_initialised();

    if (oldset) {
        const unsigned long *src = sigset_cwords(&current_mask);
        unsigned long *dst = sigset_words(oldset);
        for (size_t i = 0; i < sigset_word_count(); ++i) {
            dst[i] = src[i];
        }
    }

    if (!set) {
        return 0;
    }

    unsigned long *mask_words = sigset_words(&current_mask);
    const unsigned long *set_words = sigset_cwords(set);

    switch (how) {
    case SIG_BLOCK:
        for (size_t i = 0; i < sigset_word_count(); ++i) {
            mask_words[i] |= set_words[i];
        }
        return 0;
    case SIG_UNBLOCK:
        for (size_t i = 0; i < sigset_word_count(); ++i) {
            mask_words[i] &= ~set_words[i];
        }
        return 0;
    case SIG_SETMASK:
        for (size_t i = 0; i < sigset_word_count(); ++i) {
            mask_words[i] = set_words[i];
        }
        return 0;
    default:
        return -1;
    }
}

#define FUT_MAX_SIG 64

static struct sigaction stored_actions[FUT_MAX_SIG];
static uint8_t stored_valid[FUT_MAX_SIG];

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    if (signum <= 0 || signum >= FUT_MAX_SIG) {
        return -1;
    }

    if (oldact && stored_valid[signum]) {
        *oldact = stored_actions[signum];
    }

    if (act) {
        stored_actions[signum] = *act;
        stored_valid[signum] = 1;
    }

    return 0;
}

int raise(int sig) {
    if (sig <= 0 || sig >= FUT_MAX_SIG) {
        return -1;
    }

    if (!stored_valid[sig]) {
        return 0;
    }

    struct sigaction *act = &stored_actions[sig];
    if ((act->sa_flags & SA_SIGINFO) && act->sa_sigaction) {
        act->sa_sigaction(sig, NULL, NULL);
        return 0;
    }
    if (act->sa_handler) {
        act->sa_handler(sig);
    }
    return 0;
}
