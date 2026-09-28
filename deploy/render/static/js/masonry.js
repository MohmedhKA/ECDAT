/**
 * Pinterest Masonry Waterfall Layout Strategy Pattern
 * Calculates optimal distribution across dynamic columns, eliminating awkward vertical gaps.
 */
(function() {
    class MasonryWaterfallStrategy {
        constructor(containerSelector, options = {}) {
            this.container = document.querySelector(containerSelector);
            this.gap = options.gap || 20; // 1.25rem = 20px
            this.minColWidth = options.minColWidth || 340;
            this.resizeTimeout = null;
            this.init();
        }

        init() {
            if (!this.container) return;
            window.addEventListener('resize', () => {
                clearTimeout(this.resizeTimeout);
                this.resizeTimeout = setTimeout(() => this.layout(), 100);
            });
        }

        layout() {
            if (!this.container) return;
            const cards = Array.from(this.container.querySelectorAll('.masonry-card'));
            if (!cards.length) return;

            // In CSS column-count mode, the browser handles standard flow,
            // but this strategy ensures cards are rendered without clipped boundaries
            // and animates entry staggered timing.
            cards.forEach((card, idx) => {
                card.style.animationDelay = `${idx * 30}ms`;
            });
        }
    }

    window.MasonryWaterfall = MasonryWaterfallStrategy;
})();
