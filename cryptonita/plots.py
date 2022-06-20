import functools
from cryptonita.helpers import bisect_left_rev, bisect_right_rev


def import_plot_libs():
    import numpy as np
    import matplotlib as mpl
    import matplotlib.pyplot as plt
    import seaborn as sns

    return np, mpl, plt, sns


# See for more plot ideas:
# https://www.machinelearningplus.com/plots/top-50-matplotlib-visualizations-the-master-plots-python/


def axes_style_decorator(*style_args, **style_kargs):
    def decorator(func):
        @functools.wraps(func)
        def wrapped(*args, **kargs):
            with sns.axes_style(*style_args, **style_kargs):
                return func(*args, **kargs)

        return wrapped

    return decorator


class SequencePlotMixin:
    __slots__ = ()

    @axes_style_decorator('darkgrid')
    def plotfreq(self, n=32, fmin=1, fmax=None, ax=None, **kw):
        ''' Plot the count of each element in <self> in a bar-plot ordering
            the elements from the most common to the less.

            <self> must support the freq() method (see SequenceMixin)

            Limit the count to <n> elements. If <n> is None, no limit
            is enforced.

            Further pruning is done with <fmax> and <fmin>. If the frequency of
            an element is greather than <fmax> or less than <fmin>,
            the element will not be displayed.
            '''
        np, mpl, plt, sns = import_plot_libs()

        # Thanks to
        # https://stackoverflow.com/questions/33179122/seaborn-countplot-with-frequencies
        # https://stackoverflow.com/questions/48389751/how-do-i-get-matplotlib-to-order-bar-chart-in-the-same-order-as-my-list
        # https://matplotlib.org/3.1.1/gallery/statistics/barchart_demo.html
        autoplot = ax is None
        s = self

        fig, ax = plt.subplots()

        elems, freqs = zip(*s.freq().most_common(n))

        # prune
        ileft = 0 if fmax is None else bisect_left_rev(freqs, fmax)
        iright = bisect_right_rev(freqs, fmin, lo=ileft)

        elems = elems[ileft:iright]
        freqs = freqs[ileft:iright]

        # format
        elems = ["%02x" % e for e in elems] if isinstance(elems[0], int) else [
            e.fhex(8) for e in elems
        ]

        # percentiles
        fsums = np.cumsum(freqs)
        ftotal = fsums[-1]
        percentiles = [p * ftotal for p in [.05, .25, .5, .75, .95]]
        yticks = []
        ylabels = []
        for ix, f in enumerate(fsums):
            if f > percentiles[0]:
                while percentiles and f > percentiles[0]:
                    p = percentiles[0]
                    del percentiles[0]
                yticks.append(ix)
                ylabels.append(round(p / ftotal, 2))

                if not percentiles:
                    break

        ax.set_yticks(yticks)
        ax.set_yticklabels(ylabels)
        ax.set_ylabel('Percentile')

        # make twin axis: count and frequency
        ax2 = ax.twiny()

        ax.set_xlabel('Count')
        ax2.set_xlabel('Frequency [%]')

        # plot
        rects = ax.barh(elems, freqs, **kw)

        # annotate each bar with the formatted element
        for rect, el in zip(rects, elems):
            width = int(rect.get_width())

            # Shift the text to the right side of the right edge
            xloc = 5
            clr = 'black'
            align = 'left'

            # Center the text vertically in the bar
            yloc = rect.get_y() + rect.get_height() / 2
            ax.annotate(
                el,
                xy=(width, yloc),
                xytext=(xloc, 0),
                textcoords="offset points",
                ha=align,
                va='center_baseline',
                fontsize='small',
                color=clr,
                fontweight='demibold'
            )

        # fix the frequency range
        _, xmax = ax.get_xlim()
        ax2.set_xlim(0, (xmax / ftotal) * 100)

        ax2.grid(None)

        if autoplot:
            plt.show()

        return ax
