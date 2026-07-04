import React from 'react';
import {useCurrentFrame, interpolate} from 'remotion';
import {HIVE_COLORS} from '../constants';

// Full-bleed chrome matching TheHive's real UI (navy bar + bee mark + light
// surface), sampled live from a running instance. Fills the entire frame so
// the video reads as "screen-recorded from inside the Hive" rather than a
// mockup floating on a branded background.
export const HiveFrame: React.FC<{
	breadcrumb: string;
	aiTrackingTag: string;
	accent: string;
	children: React.ReactNode;
}> = ({breadcrumb, aiTrackingTag, accent, children}) => {
	const frame = useCurrentFrame();
	const tagIn = interpolate(frame, [16, 28], [0, 1], {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'});
	const pulse = Math.sin(frame * 0.18) * 0.5 + 0.5;

	return (
		<div style={{width: '100%', height: '100%', display: 'flex', flexDirection: 'column'}}>
			<div
				style={{
					height: 76,
					backgroundColor: HIVE_COLORS.navy,
					display: 'flex',
					alignItems: 'center',
					gap: 16,
					padding: '0 48px',
					flexShrink: 0,
				}}
			>
				<svg width={32} height={38} viewBox="0 0 28 33" fill="none">
					<path
						d="M13.8 8.3c1.8 0 3.3 1.7 3.3 3.1 0 1.6-2.7 1.8-3.2 1.8-.6 0-3.2-.1-3.2-1.8 0-1.6 1.5-3.1 3.1-3.1z"
						fill={HIVE_COLORS.beeGold}
					/>
					<path
						d="M4.7 28.1c-.5 0-.9-.1-1.3-.3-1.6-.7-2.5-2.6-1.8-4.3 1.9-4.5 7.5-7.7 10.5-8.1l-2 4.9-1.5 3.6-.9 2.2c-.6 1.3-1.8 2-3.1 2zM13.8 33c-2.2 0-4-1.6-4.7-4l9.4 0c-.7 2.5-2.5 4-4.7 4zM24 27.9c-.4.2-.9.3-1.3.3-1.3 0-2.5-.8-3-2l-1-2.2-1.4-3.4c0-.1-.1-.3-.2-.4l-1.9-4.7c3 .5 8.6 3.8 10.4 8.2.7 1.8-.1 3.7-1.8 4.4z"
						fill={HIVE_COLORS.beeGold}
					/>
				</svg>
				<span style={{color: '#fff', fontSize: 26, fontWeight: 700}}>
					The<span style={{color: HIVE_COLORS.beeGold}}>Hive</span>
				</span>
				<span style={{color: 'rgba(255,255,255,0.4)', fontSize: 20, marginLeft: 6}}>{breadcrumb}</span>

				<span
					style={{
						marginLeft: 'auto',
						opacity: tagIn,
						transform: `translateX(${interpolate(tagIn, [0, 1], [14, 0])}px)`,
						display: 'flex',
						alignItems: 'center',
						gap: 9,
						padding: '8px 18px',
						borderRadius: 999,
						border: `1px solid ${accent}80`,
						backgroundColor: `${accent}26`,
						color: accent,
						fontSize: 17,
						fontWeight: 800,
						letterSpacing: 1.5,
					}}
				>
					<span style={{position: 'relative', width: 9, height: 9}}>
						<span
							style={{
								position: 'absolute',
								inset: -6 - pulse * 5,
								borderRadius: '50%',
								backgroundColor: accent,
								opacity: 0.35 - pulse * 0.25,
							}}
						/>
						<span
							style={{
								position: 'absolute',
								inset: 0,
								borderRadius: '50%',
								backgroundColor: accent,
								boxShadow: `0 0 ${8 + pulse * 6}px ${accent}`,
							}}
						/>
					</span>
					{aiTrackingTag}
				</span>
			</div>

			<div
				style={{
					flex: 1,
					backgroundColor: HIVE_COLORS.surface,
					padding: '56px 64px',
					display: 'flex',
					flexDirection: 'column',
					gap: 28,
					overflow: 'hidden',
				}}
			>
				{children}
			</div>
		</div>
	);
};
