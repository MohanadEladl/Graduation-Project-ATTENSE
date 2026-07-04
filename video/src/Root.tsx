import React from 'react';
import {Composition} from 'remotion';
import {AttenseDemo} from './AttenseDemo';
import {FPS, TOTAL_DURATION_IN_FRAMES} from './constants';

export const Root: React.FC = () => {
	return (
		<>
			<Composition
				id="AttenseDemo"
				component={AttenseDemo}
				durationInFrames={TOTAL_DURATION_IN_FRAMES}
				fps={FPS}
				width={1320}
				height={1080}
			/>
		</>
	);
};
