import matplotlib.ticker as ticker
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

from cryptonita.helpers import bisect_left_rev, bisect_right_rev

def freq(s, n=32, fmin=1, fmax=None, ax=None, **kw):
    ''' Plot the count of each element in <s> in a bar-plot ordering
        the elements from the most common to the less.

        <s> must support the freq() method (see SequenceMixin)

        Limit the count to <n> elements. If <n> is None, no limit
        is enforced.

        Further pruning is done with <fmax> and <fmin>. If the frequency of
        an element is greather than <fmax> or less than <fmin>,
        the element will not be displayed.
        '''

    # Thanks to
    # https://stackoverflow.com/questions/33179122/seaborn-countplot-with-frequencies
    # https://stackoverflow.com/questions/48389751/how-do-i-get-matplotlib-to-order-bar-chart-in-the-same-order-as-my-list
    autoplot = ax is None

    fig, ax = plt.subplots()

    elems, freqs = zip(*s.freq().most_common(n))

    # prune
    ileft  = 0 if fmax is None else bisect_left_rev(freqs, fmax)
    iright = bisect_right_rev(freqs, fmin, lo=ileft)

    elems = elems[ileft:iright]
    freqs = freqs[ileft:iright]

    # format
    elems = ["%02x" % e for e in elems] if isinstance(elems[0], int) else [e.hex()[:6] for e in elems]

    # plot
    tmp = ax.bar(elems, freqs, **kw)

    fsums = np.cumsum(freqs)
    ftotal = fsums[-1]
    percentiles = [p * ftotal for p in [.05, .25, .5, .75, .95]]
    xticks = []
    xlabels = []
    for ix, f in enumerate(fsums):
        if f > percentiles[0]:
            while percentiles and f > percentiles[0]:
                p = percentiles[0]
                del percentiles[0]
            xticks.append(ix)
            xlabels.append(p/ftotal)

            if not percentiles:
                break

    ax.set_xticks(xticks)
    ax.set_xticklabels(xlabels)

    # annotate each bar with the formatted element
    for p, e in zip(ax.patches, elems):
        x=p.get_bbox().get_points()[:,0]
        y=p.get_bbox().get_points()[1,1]

        if len(e) <= 2:
            rot = 0
            ha = 'center'
        else:
            rot = 45
            ha = 'left'
        ax.annotate(e, (x.mean(), y),
                ha=ha, va='bottom', rotation=rot)

    # make twin axis: count and frequency
    ax2=ax.twinx()

    ax.set_ylabel('Count')
    ax2.set_ylabel('Frequency [%]')

    # fix the frequency range
    _, ymax = ax.get_ylim()
    ax2.set_ylim(0, (ymax/sum(freqs)) * 100)

    if autoplot:
        plt.show()

    return ax
