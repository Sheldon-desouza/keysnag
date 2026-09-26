// Safe: a hardcoded SVG string literal assigned to innerHTML. Must not fire
// injection.dangerous_html (an earlier version of the literal check broke on
// the internal double quotes in the width/height attributes).
export function renderIcon(el: HTMLElement): void {
  el.innerHTML = '<svg width="28" height="28"><circle r="10" /></svg>';
}
