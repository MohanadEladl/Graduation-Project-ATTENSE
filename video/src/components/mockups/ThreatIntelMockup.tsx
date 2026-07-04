import React from 'react';
import {useCurrentFrame, interpolate} from 'remotion';
import {HIVE_COLORS, COLORS} from '../../constants';
import {HiveFrame} from '../HiveFrame';

const RADIUS = 96;
const CIRC = 2 * Math.PI * RADIUS;
const FINAL_SCORE = 87;

export const ThreatIntelMockup: React.FC = () => {
	const frame = useCurrentFrame();

	const score = interpolate(frame, [8, 40], [0, FINAL_SCORE], {
		extrapolateLeft: 'clamp',
		extrapolateRight: 'clamp',
	});
	const dash = CIRC - (score / 100) * CIRC;
	const angle = -90 + (score / 100) * 360;
	const dotX = 125 + RADIUS * Math.cos((angle * Math.PI) / 180);
	const dotY = 125 + RADIUS * Math.sin((angle * Math.PI) / 180);

	const settled = score >= FINAL_SCORE - 0.5;
	const settleGlow = settled ? Math.sin((frame - 40) * 0.25) * 0.5 + 0.5 : 0;

	const sourcesIn = interpolate(frame, [14, 26], [0, 1], {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'});

	const SOURCES = [
		{label: 'AbuseIPDB — 92% confidence', color: COLORS.amber, pingStart: 30},
		{label: 'VirusTotal — 14 vendors flagged', color: COLORS.red, pingStart: 44},
	];

	return (
		<HiveFrame breadcrumb="/ Observables / 185.220.101.47" aiTrackingTag="AI TRACKING — SCORING" accent={COLORS.amber}>
			<div style={{color: 'rgba(0,0,0,0.4)', fontSize: 22, letterSpacing: 2, fontWeight: 700}}>
				THREAT INTEL — ENRICHED BY ATTENSE AI
			</div>
			<div style={{display: 'flex', alignItems: 'center', gap: 80, flex: 1, maxWidth: 1300}}>
				<div style={{position: 'relative', width: 250, height: 250, flexShrink: 0}}>
					<svg width={250} height={250} viewBox="0 0 250 250">
						<circle cx={125} cy={125} r={RADIUS} fill="none" stroke="rgba(0,0,0,0.08)" strokeWidth={18} />
						<circle
							cx={125}
							cy={125}
							r={RADIUS}
							fill="none"
							stroke={COLORS.amber}
							strokeWidth={18}
							strokeLinecap="round"
							strokeDasharray={CIRC}
							strokeDashoffset={dash}
							transform="rotate(-90 125 125)"
							style={{
								filter: settled ? `drop-shadow(0 0 ${6 + settleGlow * 8}px ${COLORS.amber}90)` : undefined,
							}}
						/>
						{score > 0 && score < 100 && (
							<circle cx={dotX} cy={dotY} r={9} fill={COLORS.amber} style={{filter: `drop-shadow(0 0 6px ${COLORS.amber})`}} />
						)}
					</svg>
					<div
						style={{
							position: 'absolute',
							inset: 0,
							display: 'flex',
							flexDirection: 'column',
							alignItems: 'center',
							justifyContent: 'center',
						}}
					>
						<span
							style={{
								color: HIVE_COLORS.textDark,
								fontSize: 60,
								fontWeight: 800,
								textShadow: settled ? `0 0 ${10 + settleGlow * 14}px ${COLORS.amber}70` : undefined,
							}}
						>
							{Math.round(score)}
						</span>
						<span style={{color: 'rgba(0,0,0,0.4)', fontSize: 16, letterSpacing: 2, fontWeight: 700}}>RISK SCORE</span>
					</div>
				</div>

				<div
					style={{
						display: 'flex',
						flexDirection: 'column',
						gap: 22,
						opacity: sourcesIn,
						backgroundColor: HIVE_COLORS.surfaceWhite,
						borderRadius: 16,
						padding: '36px 40px',
						border: '1px solid rgba(0,0,0,0.06)',
						boxShadow: '0 10px 30px -16px rgba(0,0,0,0.25)',
						flex: 1,
					}}
				>
					{SOURCES.map((src) => {
						const local = frame - src.pingStart;
						const ping = local >= 0 ? Math.max(0, 1 - (local % 40) / 40) : 0;
						return (
							<div key={src.label} style={{display: 'flex', alignItems: 'center', gap: 16}}>
								<span style={{position: 'relative', width: 14, height: 14}}>
									{local >= 0 && (
										<span
											style={{
												position: 'absolute',
												inset: -ping * 10,
												borderRadius: '50%',
												backgroundColor: src.color,
												opacity: ping * 0.4,
											}}
										/>
									)}
									<span style={{position: 'absolute', inset: 0, borderRadius: '50%', backgroundColor: src.color}} />
								</span>
								<span style={{color: HIVE_COLORS.textDark, fontSize: 26}}>{src.label}</span>
							</div>
						);
					})}
				</div>
			</div>
		</HiveFrame>
	);
};
