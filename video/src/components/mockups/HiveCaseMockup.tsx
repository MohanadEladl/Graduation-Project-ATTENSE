import React from 'react';
import {useCurrentFrame, interpolate} from 'remotion';
import {HIVE_COLORS, COLORS} from '../../constants';
import {HiveFrame} from '../HiveFrame';

const OBSERVABLES = [
	{type: 'ip', value: '185.220.101.47'},
	{type: 'hash', value: 'a13f9c7e2b6d4480e9f1c0a2b8d6e9e02'},
	{type: 'url', value: 'hxxp://mal.lab/payload'},
];

const TITLE = 'SQL Injection Attempt';

export const HiveCaseMockup: React.FC = () => {
	const frame = useCurrentFrame();

	const caseIn = interpolate(frame, [10, 22], [0, 1], {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'});

	const titleProgress = interpolate(frame, [16, 16 + TITLE.length * 1.6], [0, TITLE.length], {
		extrapolateLeft: 'clamp',
		extrapolateRight: 'clamp',
	});
	const titleChars = Math.floor(titleProgress);
	const caretOn = Math.floor(frame / 8) % 2 === 0;
	const titleDone = titleChars >= TITLE.length;

	const tagPop = interpolate(frame, [38, 48], [0, 1], {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'});

	// AI scan beam sweeping down the observable list
	const beamProgress = interpolate(frame, [56, 92], [0, 1], {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'});
	const beamActive = beamProgress > 0 && beamProgress < 1;

	return (
		<HiveFrame breadcrumb="/ Cases / #2418" aiTrackingTag="AI TRACKING — ON" accent={COLORS.red}>
			<div
				style={{
					opacity: caseIn,
					transform: `translateY(${interpolate(caseIn, [0, 1], [22, 0])}px)`,
					backgroundColor: HIVE_COLORS.surfaceWhite,
					borderRadius: 16,
					padding: '32px 36px',
					border: '1px solid rgba(0,0,0,0.06)',
					boxShadow: '0 10px 30px -16px rgba(0,0,0,0.25)',
					maxWidth: 1300,
				}}
			>
				<div style={{color: 'rgba(0,0,0,0.4)', fontSize: 18, letterSpacing: 2, fontWeight: 700}}>
					CASE #2418 — AUTO-CREATED BY ATTENSE
				</div>
				<div style={{color: HIVE_COLORS.textDark, fontSize: 38, fontWeight: 700, marginTop: 10, minHeight: 48}}>
					{TITLE.slice(0, titleChars)}
					{!titleDone && <span style={{opacity: caretOn ? 1 : 0, color: COLORS.red}}>|</span>}
				</div>
				<div
					style={{
						display: 'inline-flex',
						alignItems: 'center',
						gap: 8,
						marginTop: 16,
						padding: '8px 18px',
						borderRadius: 8,
						backgroundColor: `${COLORS.red}1f`,
						color: COLORS.red,
						fontSize: 18,
						fontWeight: 700,
						fontFamily: "'Cascadia Code', 'Consolas', monospace",
						opacity: tagPop,
						transform: `scale(${interpolate(tagPop, [0, 0.7, 1], [0.6, 1.12, 1])})`,
					}}
				>
					attense:incident-2418
				</div>
			</div>

			<div style={{display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 1300, position: 'relative'}}>
				<div style={{color: 'rgba(0,0,0,0.4)', fontSize: 18, letterSpacing: 2, fontWeight: 700}}>
					OBSERVABLES — TRACKED BY AI
				</div>

				{beamActive && (
					<div
						style={{
							position: 'absolute',
							left: 0,
							right: 0,
							top: `${56 + beamProgress * 44}px`,
							height: 3,
							background: `linear-gradient(90deg, transparent, ${COLORS.red}, transparent)`,
							boxShadow: `0 0 16px 2px ${COLORS.red}80`,
						}}
					/>
				)}

				{OBSERVABLES.map((obs, i) => {
					const start = 30 + i * 7;
					const reveal = interpolate(frame, [start, start + 8], [0, 1], {
						extrapolateLeft: 'clamp',
						extrapolateRight: 'clamp',
					});
					const tracked = interpolate(frame, [60 + i * 6, 68 + i * 6], [0, 1], {
						extrapolateLeft: 'clamp',
						extrapolateRight: 'clamp',
					});
					return (
						<div
							key={obs.value}
							style={{
								opacity: reveal,
								transform: `translateX(${interpolate(reveal, [0, 1], [26, 0])}px)`,
								display: 'flex',
								alignItems: 'center',
								gap: 16,
								fontSize: 22,
								fontFamily: "'Cascadia Code', 'Consolas', monospace",
							}}
						>
							<span
								style={{
									color: COLORS.red,
									border: `1px solid ${COLORS.red}55`,
									borderRadius: 6,
									padding: '3px 10px',
									fontSize: 15,
									fontWeight: 700,
									backgroundColor: `${COLORS.red}10`,
								}}
							>
								{obs.type}
							</span>
							<span style={{color: HIVE_COLORS.textDark}}>{obs.value}</span>
							{tracked > 0 && (
								<span
									style={{
										display: 'inline-flex',
										alignItems: 'center',
										gap: 6,
										marginLeft: 6,
										fontSize: 13,
										fontWeight: 700,
										letterSpacing: 1,
										color: COLORS.red,
										opacity: tracked,
									}}
								>
									<span
										style={{
											width: 7,
											height: 7,
											borderRadius: '50%',
											backgroundColor: COLORS.red,
											boxShadow: `0 0 8px ${COLORS.red}`,
											transform: `scale(${0.8 + Math.sin((frame - 60 - i * 6) * 0.3) * 0.3})`,
										}}
									/>
									TRACKED
								</span>
							)}
						</div>
					);
				})}
			</div>
		</HiveFrame>
	);
};
