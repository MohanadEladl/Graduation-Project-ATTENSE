import React from 'react';
import {AbsoluteFill, Sequence} from 'remotion';
import {HIVE_COLORS, TIMELINE} from './constants';
import {Scene} from './components/Scene';
import {AlertQueueMockup} from './components/mockups/AlertQueueMockup';
import {HiveCaseMockup} from './components/mockups/HiveCaseMockup';
import {ThreatIntelMockup} from './components/mockups/ThreatIntelMockup';
import {ContainmentMockup} from './components/mockups/ContainmentMockup';

export const AttenseDemo: React.FC = () => {
	return (
		<AbsoluteFill style={{backgroundColor: HIVE_COLORS.navy}}>
			<Sequence from={TIMELINE.alerts.from} durationInFrames={TIMELINE.alerts.durationInFrames}>
				<Scene durationInFrames={TIMELINE.alerts.durationInFrames} background={HIVE_COLORS.surface}>
					<AlertQueueMockup />
				</Scene>
			</Sequence>

			<Sequence from={TIMELINE.caseView.from} durationInFrames={TIMELINE.caseView.durationInFrames}>
				<Scene durationInFrames={TIMELINE.caseView.durationInFrames} background={HIVE_COLORS.surface}>
					<HiveCaseMockup />
				</Scene>
			</Sequence>

			<Sequence from={TIMELINE.threatIntel.from} durationInFrames={TIMELINE.threatIntel.durationInFrames}>
				<Scene durationInFrames={TIMELINE.threatIntel.durationInFrames} background={HIVE_COLORS.surface}>
					<ThreatIntelMockup />
				</Scene>
			</Sequence>

			<Sequence from={TIMELINE.containment.from} durationInFrames={TIMELINE.containment.durationInFrames}>
				<Scene durationInFrames={TIMELINE.containment.durationInFrames} background={HIVE_COLORS.surface}>
					<ContainmentMockup />
				</Scene>
			</Sequence>
		</AbsoluteFill>
	);
};
