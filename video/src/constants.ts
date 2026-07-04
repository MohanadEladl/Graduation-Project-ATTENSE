export const COLORS = {
	background: '#18100a',
	panel: '#1c1209',
	panelLight: '#2b1d11',
	text: '#f0ebe0',
	muted: '#a8957f',
	red: '#c04d2a',
	redSoft: '#9a3c21',
	violet: '#d4844e',
	cyan: '#e3ac82',
	amber: '#d4844e',
	mint: '#e8d4b8',
	gold: '#d4844e',
} as const;

// Colors sampled live from a running TheHive 5.2 instance (computed styles + logo SVG)
export const HIVE_COLORS = {
	navy: '#1b1b34',
	beeGold: '#e9cf42',
	accentBlue: '#1890ff',
	surface: '#f9f9f9',
	surfaceWhite: '#ffffff',
	textDark: 'rgba(0,0,0,0.85)',
} as const;

export const FONT_FAMILY =
	"'Segoe UI', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif";

export const FPS = 30;

// Scene frame ranges (cumulative timeline, 14s total) — four full-screen
// panels shot "from inside the Hive", crossfading into one another.
export const TIMELINE = {
	alerts: {from: 0, durationInFrames: 105},
	caseView: {from: 105, durationInFrames: 105},
	threatIntel: {from: 210, durationInFrames: 105},
	containment: {from: 315, durationInFrames: 105},
} as const;

export const TOTAL_DURATION_IN_FRAMES = 420;
