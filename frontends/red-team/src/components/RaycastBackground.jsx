import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { MeshTransmissionMaterial, Instances, Instance, PerspectiveCamera } from '@react-three/drei'
import { useRef, useMemo, useEffect } from 'react'
import * as THREE from 'three'
import { easing } from 'maath'

/* ─────────────────────────────────────────────────────────────
   1:1 port of Raycast's homepage WebGL hero background.
   Scene, GLSL, config and animation extracted verbatim from the
   raycast.com production bundle (chunks 5621 + 483).
   ───────────────────────────────────────────────────────────── */

const CONFIG = {
  scene: {
    backgroundColor: { r: 7, g: 9, b: 10 },
    cubeZ: -9, cubeY: 0, glassZ: 0, glassRotation: 0.73, cameraZ: 16.54,
  },
  glass: {
    thickness: 1, roughness: 0.35, anisotropicBlur: 2.88, ior: 1.5,
    resolution: 1024, chromaticAberration: 3, distortion: 0,
    distortionScale: 0.08, temporalDistortion: 0, transmission: 1,
    samples: 6, animateDistortion: true,
  },
  cylinder: { count: 16, radius: 0.5, height: 15, subdivisions: 8 },
  cubeShader: {
    speed: 0.1, size: 0.99,
    color1: { r: 244, g: 254, b: 255 }, // highlights (near-white)
    color2: { r: 255, g: 122, b: 152 }, // midtone pink
    color3: { r: 184, g: 2,   b: 50  }, // deep red
  },
  cubeInteraction: { enabled: true, rotationInfluence: 0.3 },
}

const toVec3 = (c) => new THREE.Vector3(c.r / 255, c.g / 255, c.b / 255)

/* easeInExpo — exact easing passed to damp in the original */
const easeInExpo = (e) => (e === 0 ? 0 : Math.pow(2, 10 * e - 10))

/* ── Cube background shader (verbatim) ── */
const CUBE_VERT = `
varying vec2 vUv;
void main() {
  vUv = uv;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.);
}`

const CUBE_FRAG = `
uniform float uTime;
uniform float uSpeed;
uniform float uSize;
uniform vec3 uColor1;
uniform vec3 uColor2;
uniform vec3 uColor3;
uniform vec2 uResolution;
varying vec2 vUv;

float w1 = 3.0;
float w2 = 1.0;
float w3 = 20.0;
float A = 1.0;
float R = 3.0;

float horizontal(in vec2 xy, float t) {
  float v = cos(w1 * xy.x + A * t);
  return v;
}
float diagonal(in vec2 xy, float t) {
  float v = cos(w2 * (xy.x * cos(t) + 5.0 * xy.y * sin(t)) + A * t);
  return v;
}
float radial(in vec2 xy, float t) {
  float x = 0.3 * xy.x - 0.5 + cos(t);
  float y = 0.3 * xy.y - 0.5 + sin(t * 0.5);
  float v = sin(w3 * sqrt(x * x + y * y + 1.0) + A * t);
  return v;
}

void main() {
  float t = uTime * uSpeed + 10000.;
  vec2 scaledXY = gl_FragCoord.xy / uResolution.xy - 0.5;
  scaledXY *= uSize;
  scaledXY += 0.5;
  vec2 xy = scaledXY;
  float v = (horizontal(xy, t) + diagonal(xy, t) + radial(xy, t)) / 3.0;
  float nv = (v + 1.0) * 0.5;
  vec3 color;
  if (nv < 0.5) {
    color = mix(uColor3, uColor2, nv * 2.0);
  } else {
    color = mix(uColor2, uColor1, (nv - 0.5) * 2.0);
  }
  gl_FragColor = vec4(pow(color, vec3(R)), 1.0);
}`

/* ── Glass rods + exact distortion animation ── */
function GlassRods({ glass, cyl }) {
  const matRef = useRef(null)
  const viewport = useThree((s) => s.viewport)

  const objects = useMemo(() => {
    const e = 2 * cyl.radius
    return Array.from({ length: cyl.count }).map((_, o) => {
      const t = new THREE.Object3D()
      t.position.set((o + e) * e - (e * cyl.count) / 2, 0, 0)
      return t
    })
  }, [cyl])

  useFrame((state, delta) => {
    if (matRef.current && viewport.width > 7.3 && glass.animateDistortion) {
      easing.damp(matRef.current.uniforms.distortion, 'value', 15, 30, delta, 2e-4, easeInExpo)
      easing.damp(matRef.current.uniforms.temporalDistortion, 'value', 0.025, 10, delta, 2e-4, easeInExpo)
    }
    if (state.clock.getElapsedTime() > 200) state.setFrameloop('never')
  })

  return (
    <group>
      <Instances range={objects.length} frustumCulled={false}>
        <cylinderGeometry args={[cyl.radius, cyl.radius, cyl.height, cyl.subdivisions, 1]} />
        <MeshTransmissionMaterial
          ref={matRef}
          transmission={glass.transmission}
          thickness={glass.thickness}
          roughness={glass.roughness}
          chromaticAberration={glass.chromaticAberration}
          anisotropicBlur={glass.anisotropicBlur}
          distortion={glass.distortion}
          distortionScale={glass.distortionScale}
          temporalDistortion={glass.temporalDistortion}
          ior={glass.ior}
          resolution={glass.resolution}
          samples={glass.samples}
          specularIntensity={0}
        />
        {objects.map((o, i) => (
          <Instance key={i} position={o.position} />
        ))}
      </Instances>
    </group>
  )
}

/* ── Animated colour cube + exact intro/mouse animation ── */
function Cube({ scene, cubeShader, interaction }) {
  const ref = useRef(null)
  const mouse = useRef({ x: 0, y: 0 })

  const uniforms = useMemo(() => ({
    uTime:   { value: 0 },
    uSpeed:  { value: cubeShader.speed },
    uSize:   { value: cubeShader.size },
    uColor1: { value: toVec3(cubeShader.color1) },
    uColor2: { value: toVec3(cubeShader.color2) },
    uColor3: { value: toVec3(cubeShader.color3) },
    uResolution: { value: new THREE.Vector2(1, 1) },
  }), [cubeShader])

  useEffect(() => {
    const onMove = (e) => {
      mouse.current = {
        x: (e.clientX / window.innerWidth) * 2 - 1,
        y: -((e.clientY / window.innerHeight) * 2) + 1,
      }
    }
    window.addEventListener('mousemove', onMove)
    return () => window.removeEventListener('mousemove', onMove)
  }, [])

  useFrame((state, delta) => {
    if (!ref.current) return
    const u = ref.current.material.uniforms
    u.uTime.value = state.clock.getElapsedTime()
    u.uSpeed.value = cubeShader.speed
    u.uSize.value = cubeShader.size
    u.uResolution.value.set(state.size.width, state.size.height)
    // intro grow from scale 0 → 1
    easing.damp3(ref.current.scale, [1, 1, 1], 1, delta)
    // tilt toward mouse
    if (interaction.enabled) {
      const s = interaction.rotationInfluence
      easing.dampE(
        ref.current.rotation,
        [mouse.current.x * s, -mouse.current.y * s, ref.current.rotation.z],
        0.5,
        delta,
      )
    }
  })

  return (
    <mesh ref={ref} name="Cube" position={[0, scene.cubeY, scene.cubeZ]} scale={0}>
      <boxGeometry args={[7, 7, 7]} />
      <shaderMaterial
        uniforms={uniforms}
        vertexShader={CUBE_VERT}
        fragmentShader={CUBE_FRAG}
        side={THREE.FrontSide}
      />
    </mesh>
  )
}

function Scene() {
  const { scene, glass, cylinder, cubeShader, cubeInteraction } = CONFIG
  return (
    <>
      <color attach="background" args={[scene.backgroundColor.r / 255, scene.backgroundColor.g / 255, scene.backgroundColor.b / 255]} />
      <group position={[0, 0, scene.glassZ]} rotation={[0, 0, scene.glassRotation]}>
        <GlassRods glass={glass} cyl={cylinder} />
      </group>
      <Cube scene={scene} cubeShader={cubeShader} interaction={cubeInteraction} />
      <PerspectiveCamera makeDefault far={100} near={0.01} fov={35} position={[0, 0, scene.cameraZ]} rotation={[0, 0, 0]} />
    </>
  )
}

export default function RaycastBackground({ className, style }) {
  return (
    <Canvas
      className={className}
      style={style}
      linear
      flat
      frameloop="always"
      dpr={2}
      gl={{ preserveDrawingBuffer: true, antialias: true }}
    >
      <Scene />
    </Canvas>
  )
}
