import { useEffect, useRef } from 'react'
import * as THREE from 'three'

/**
 * Minimal particle field — 60 tiny white dots, barely visible, very slow.
 * The effect is "dark sky with stars", not "network visualization".
 * No connection lines, no color variety, no animation chaos.
 */
export default function ParticleBackground() {
  const mountRef = useRef(null)

  useEffect(() => {
    const mount = mountRef.current
    if (!mount) return

    const scene  = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(60, mount.clientWidth / mount.clientHeight, 0.1, 1000)
    camera.position.z = 80

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(mount.clientWidth, mount.clientHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setClearColor(0x000000, 0)
    mount.appendChild(renderer.domElement)

    const COUNT = 60
    const positions = new Float32Array(COUNT * 3)

    for (let i = 0; i < COUNT; i++) {
      positions[i * 3]     = (Math.random() - 0.5) * 180
      positions[i * 3 + 1] = (Math.random() - 0.5) * 180
      positions[i * 3 + 2] = (Math.random() - 0.5) * 80
    }

    const geo = new THREE.BufferGeometry()
    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3))

    const mat = new THREE.PointsMaterial({
      size: 0.6,
      color: 0xffffff,
      transparent: true,
      opacity: 0.18,
      sizeAttenuation: true,
    })

    const points = new THREE.Points(geo, mat)
    scene.add(points)

    let frame
    const animate = () => {
      frame = requestAnimationFrame(animate)
      points.rotation.y += 0.00008
      points.rotation.x += 0.00004
      renderer.render(scene, camera)
    }
    animate()

    const resize = () => {
      camera.aspect = mount.clientWidth / mount.clientHeight
      camera.updateProjectionMatrix()
      renderer.setSize(mount.clientWidth, mount.clientHeight)
    }
    window.addEventListener('resize', resize)

    return () => {
      cancelAnimationFrame(frame)
      window.removeEventListener('resize', resize)
      renderer.dispose()
      if (mount.contains(renderer.domElement)) mount.removeChild(renderer.domElement)
    }
  }, [])

  return (
    <div ref={mountRef} className="fixed inset-0 pointer-events-none z-0" />
  )
}
