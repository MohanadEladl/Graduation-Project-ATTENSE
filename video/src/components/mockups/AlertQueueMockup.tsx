import React from 'react';
import {useCurrentFrame, useVideoConfig, spring, interpolate} from 'remotion';
import {HIVE_COLORS, COLORS} from '../../constants';
import {HiveFrame} from '../HiveFrame';

const ALERTS = [
	{label: 'Brute force — auth.attense.lab', severity: 'HIGH', verdict: 'TRUE POSITIVE', flagged: true},
	{label: 'Port scan — 10.0.4.18', severity: 'LOW', verdict: 'FALSE POSITIVE', flagged: false},
	{label: 'SQLi attempt — /search', severity: 'CRIT', verdict: 'TRUE POSITIVE', flagged: true},
	{label: 'Unusual login time — jdoe', severity: 'MED', verdict: 'FALSE POSITIVE', flagged: false},
];

export const AlertQueueMockup: React.FC = () => {
	const frame = useCurrentFrame();
	const {fps} = useVideoConfig();

	return (
		<HiveFrame breadcrumb="/ Alerts — live feed" aiTrackingTag="AI TRACKING — LIVE" accent={COLORS.red}>
			<div style={{color: 'rgba(0,0,0,0.4)', fontSize: 22, letterSpacing: 2, fontWeight: 700}}>
				INCOMING QUEUE — CLASSIFIED BY ATTENSE AI
			</div>
			<div style={{display: 'flex', flexDirection: 'column', gap: 22, flex: 1, justifyContent: 'center', maxWidth: 1300}}>
				{ALERTS.map((alert, i) => {
					const start = 6 + i * 9;
					const reveal = spring({frame: frame - start, fps, config: {damping: 13, mass: 0.6}, durationInFrames: 16});
					const slide = interpolate(reveal, [0, 1], [50, 0]);

					const scanStart = start + 8;
					const scanProgress = interpolate(frame, [scanStart, scanStart + 14], [0, 1], {
						extrapolateLeft: 'clamp',
						extrapolateRight: 'clamp',
					});
					const scanning = scanProgress > 0 && scanProgress < 1;

					const classified = interpolate(frame, [scanStart + 8, scanStart + 16], [0, 1], {
						extrapolateLeft: 'clamp',
						extrapolateRight: 'clamp',
					});
					const verdictColor = alert.flagged ? COLORS.red : 'rgba(0,0,0,0.35)';

					return (
						<div
							key={alert.label}
							style={{
								opacity: Math.min(reveal, 1),
								transform: `translateX(${slide}px)`,
								position: 'relative',
								display: 'flex',
								alignItems: 'center',
								gap: 22,
								padding: '24px 30px',
								borderRadius: 14,
								backgroundColor: HIVE_COLORS.surfaceWhite,
								border: `1px solid ${classified > 0.4 && alert.flagged ? `${COLORS.red}40` : 'rgba(0,0,0,0.06)'}`,
								boxShadow: '0 10px 30px -16px rgba(0,0,0,0.25)',
								overflow: 'hidden',
							}}
						>
							{scanning && (
								<div
									style={{
										position: 'absolute',
										inset: 0,
										background: `linear-gradient(100deg, transparent 0%, transparent ${
											scanProgress * 100 - 14
										}%, ${COLORS.amber}33 ${scanProgress * 100 - 4}%, ${COLORS.amber}55 ${
											scanProgress * 100
										}%, ${COLORS.amber}33 ${scanProgress * 100 + 4}%, transparent ${
											scanProgress * 100 + 14
										}%, transparent 100%)`,
									}}
								/>
							)}
							<span
								style={{
									fontSize: 16,
									fontWeight: 800,
									letterSpacing: 1.5,
									color: HIVE_COLORS.accentBlue,
									border: `1px solid ${HIVE_COLORS.accentBlue}55`,
									borderRadius: 7,
									padding: '5px 12px',
									flexShrink: 0,
									position: 'relative',
								}}
							>
								{alert.severity}
							</span>
							<span style={{color: HIVE_COLORS.textDark, fontSize: 24, flex: 1, position: 'relative'}}>
								{alert.label}
							</span>
							{scanning && (
								<span
									style={{
										fontSize: 13,
										fontWeight: 700,
										letterSpacing: 1,
										color: COLORS.amber,
										position: 'relative',
									}}
								>
									ANALYZING…
								</span>
							)}
							{classified > 0.5 && (
								<span
									style={{
										fontSize: 16,
										fontWeight: 700,
										letterSpacing: 0.8,
										color: verdictColor,
										opacity: classified,
										transform: `scale(${interpolate(classified, [0, 1], [0.7, 1])})`,
										position: 'relative',
									}}
								>
									{alert.verdict}
								</span>
							)}
						</div>
					);
				})}
			</div>
		</HiveFrame>
	);
};
