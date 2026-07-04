import React from 'react';
import {useCurrentFrame, interpolate} from 'remotion';
import {HIVE_COLORS, COLORS} from '../../constants';
import {HiveFrame} from '../HiveFrame';

const PLAYBOOKS = [
	{label: 'Command Injection'},
	{label: 'Cross-Site Scripting'},
	{label: 'Directory Traversal'},
	{label: 'Broken Auth'},
];

export const ContainmentMockup: React.FC = () => {
	const frame = useCurrentFrame();

	return (
		<HiveFrame breadcrumb="/ Cases / #2418 / Response" aiTrackingTag="AI TRACKING — RESPONDING" accent={COLORS.mint}>
			<div style={{display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', maxWidth: 1300}}>
				<div style={{color: 'rgba(0,0,0,0.4)', fontSize: 22, letterSpacing: 2, fontWeight: 700}}>
					CONTAINMENT PLAYBOOKS — RUN BY ATTENSE AI
				</div>
				<div style={{color: COLORS.red, fontSize: 22, fontWeight: 700}}>TTC &lt; 5 min</div>
			</div>
			<div
				style={{
					display: 'flex',
					flexDirection: 'column',
					gap: 28,
					backgroundColor: HIVE_COLORS.surfaceWhite,
					borderRadius: 16,
					padding: '36px 44px',
					border: '1px solid rgba(0,0,0,0.06)',
					boxShadow: '0 10px 30px -16px rgba(0,0,0,0.25)',
					flex: 1,
					justifyContent: 'center',
					maxWidth: 1300,
				}}
			>
				{PLAYBOOKS.map((pb, i) => {
					const start = 8 + i * 9;
					const progress = interpolate(frame, [start, start + 16], [0, 1], {
						extrapolateLeft: 'clamp',
						extrapolateRight: 'clamp',
					});
					const justFinished = progress > 0.92 && progress < 1;
					const done = progress >= 1;
					const pop = justFinished ? interpolate(progress, [0.92, 0.96, 1], [0.85, 1.18, 1]) : 1;
					const running = progress > 0 && progress < 0.92;
					const shimmerX = interpolate(frame % 40, [0, 40], [-60, 260]);

					return (
						<div key={pb.label} style={{display: 'flex', alignItems: 'center', gap: 24}}>
							<span
								style={{
									color: done ? HIVE_COLORS.textDark : 'rgba(0,0,0,0.55)',
									fontSize: 24,
									fontWeight: 600,
									width: 280,
									flexShrink: 0,
								}}
							>
								{pb.label}
							</span>
							<div
								style={{
									flex: 1,
									height: 16,
									borderRadius: 8,
									backgroundColor: 'rgba(0,0,0,0.07)',
									overflow: 'hidden',
									position: 'relative',
								}}
							>
								<div
									style={{
										position: 'absolute',
										inset: 0,
										width: `${progress * 100}%`,
										backgroundColor: done ? COLORS.red : COLORS.amber,
										borderRadius: 8,
										overflow: 'hidden',
									}}
								>
									{running && (
										<div
											style={{
												position: 'absolute',
												top: 0,
												bottom: 0,
												left: shimmerX,
												width: 50,
												background:
													'linear-gradient(90deg, transparent, rgba(255,255,255,0.55), transparent)',
											}}
										/>
									)}
								</div>
							</div>
							<span
								style={{
									display: 'inline-block',
									color: done ? COLORS.red : 'rgba(0,0,0,0.4)',
									fontSize: 18,
									fontWeight: 700,
									width: 140,
									textAlign: 'right',
									flexShrink: 0,
									transform: `scale(${pop})`,
								}}
							>
								{done ? 'CONTAINED' : running ? `${Math.round(progress * 100)}%` : 'queued…'}
							</span>
						</div>
					);
				})}
			</div>
		</HiveFrame>
	);
};
