import React from 'react';
import {AbsoluteFill} from 'remotion';
import {COLORS, FONT_FAMILY} from '../constants';

export const Scene: React.FC<{
	durationInFrames: number;
	background?: string;
	children: React.ReactNode;
}> = ({background = COLORS.background, children}) => {
	return (
		<AbsoluteFill
			style={{
				backgroundColor: background,
				fontFamily: FONT_FAMILY,
			}}
		>
			{children}
		</AbsoluteFill>
	);
};
