import { useEffect, useRef } from 'react'
import * as THREE from 'three'

/**
 * Premium interactive 3D particle network.
 * Renders nodes that slowly drift and bounce within bounds.
 * Faint connecting lines dynamically appear between close nodes.
 * The entire network gently tilts in response to mouse movements.
 */
export default function ParticleBackground() {
  const mountRef = useRef(null)

  useEffect(() => {
    const mount = mountRef.current
    if (!mount) return

    const scene  = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(60, mount.clientWidth / mount.clientHeight, 0.1, 1000)
    camera.position.z = 75

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(mount.clientWidth, mount.clientHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setClearColor(0x030303, 0)
    mount.appendChild(renderer.domElement)

    // Generate random nodes
    const COUNT = 85
    const areaSize = 120
    const positions = new Float32Array(COUNT * 3)
    const velocities = []

    for (let i = 0; i < COUNT; i++) {
      positions[i * 3]     = (Math.random() - 0.5) * areaSize * 1.6
      positions[i * 3 + 1] = (Math.random() - 0.5) * areaSize
      positions[i * 3 + 2] = (Math.random() - 0.5) * areaSize * 0.8
      
      velocities.push({
        x: (Math.random() - 0.5) * 0.06,
        y: (Math.random() - 0.5) * 0.06,
        z: (Math.random() - 0.5) * 0.03
      })
    }

    const pointsGeo = new THREE.BufferGeometry()
    pointsGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3))

    // Circle texture with soft center and custom color halo matching the theme accent
    const createCircleTexture = () => {
      const canvas = document.createElement('canvas')
      canvas.width = 32
      canvas.height = 32
      const ctx = canvas.getContext('2d')
      const grad = ctx.createRadialGradient(16, 16, 0, 16, 16, 16)
      grad.addColorStop(0, 'rgba(255, 255, 255, 1)')
      grad.addColorStop(0.25, 'rgba(10, 132, 255, 0.85)')
      grad.addColorStop(0.6, 'rgba(0, 112, 243, 0.25)')
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)')
      ctx.fillStyle = grad
      ctx.fillRect(0, 0, 32, 32)
      return new THREE.CanvasTexture(canvas)
    }

    const pointsMat = new THREE.PointsMaterial({
      size: 2.4,
      map: createCircleTexture(),
      transparent: true,
      opacity: 0.7,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    })

    const points = new THREE.Points(pointsGeo, pointsMat)
    scene.add(points)

    // Connection lines setup
    const maxLines = COUNT * 4
    const linePositions = new Float32Array(maxLines * 6)
    const lineColors = new Float32Array(maxLines * 6)

    const linesGeo = new THREE.BufferGeometry()
    linesGeo.setAttribute('position', new THREE.BufferAttribute(linePositions, 3))
    linesGeo.setAttribute('color', new THREE.BufferAttribute(lineColors, 3))

    const linesMat = new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      opacity: 0.18,
      blending: THREE.AdditiveBlending,
      depthWrite: false
    })

    const lines = new THREE.LineSegments(linesGeo, linesMat)
    scene.add(lines)

    // Interactive cursor state
    let targetRotationX = 0
    let targetRotationY = 0

    const onMouseMove = (e) => {
      const windowHalfX = window.innerWidth / 2
      const windowHalfY = window.innerHeight / 2
      const mouseX = (e.clientX - windowHalfX) / windowHalfX
      const mouseY = (e.clientY - windowHalfY) / windowHalfY
      targetRotationY = mouseX * 0.22
      targetRotationX = mouseY * 0.22
    }
    window.addEventListener('mousemove', onMouseMove, { passive: true })

    // Animation Loop
    let frame
    const animate = () => {
      frame = requestAnimationFrame(animate)

      // Move points
      const posArr = pointsGeo.attributes.position.array
      for (let i = 0; i < COUNT; i++) {
        posArr[i * 3]     += velocities[i].x
        posArr[i * 3 + 1] += velocities[i].y
        posArr[i * 3 + 2] += velocities[i].z

        const boundaryX = areaSize * 0.8
        const boundaryY = areaSize * 0.5
        const boundaryZ = areaSize * 0.4
        if (Math.abs(posArr[i * 3]) > boundaryX) velocities[i].x *= -1
        if (Math.abs(posArr[i * 3 + 1]) > boundaryY) velocities[i].y *= -1
        if (Math.abs(posArr[i * 3 + 2]) > boundaryZ) velocities[i].z *= -1
      }
      pointsGeo.attributes.position.needsUpdate = true

      // Dynamic network lines
      let lineIndex = 0
      const maxDistance = 30
      const linePosArr = linesGeo.attributes.position.array
      const lineColorArr = linesGeo.attributes.color.array

      for (let i = 0; i < COUNT; i++) {
        const x1 = posArr[i * 3]
        const y1 = posArr[i * 3 + 1]
        const z1 = posArr[i * 3 + 2]

        for (let j = i + 1; j < COUNT; j++) {
          if (lineIndex >= maxLines) break

          const x2 = posArr[j * 3]
          const y2 = posArr[j * 3 + 1]
          const z2 = posArr[j * 3 + 2]

          const dx = x1 - x2
          const dy = y1 - y2
          const dz = z1 - z2
          const dist = Math.sqrt(dx * dx + dy * dy + dz * dz)

          if (dist < maxDistance) {
            // Position
            linePosArr[lineIndex * 6]     = x1
            linePosArr[lineIndex * 6 + 1] = y1
            linePosArr[lineIndex * 6 + 2] = z1
            linePosArr[lineIndex * 6 + 3] = x2
            linePosArr[lineIndex * 6 + 4] = y2
            linePosArr[lineIndex * 6 + 5] = z2

            // Faint glow color mix based on distance
            const ratio = 1 - dist / maxDistance
            const r = 0.15 + 0.1 * ratio
            const g = 0.18 + 0.22 * ratio
            const b = 0.35 + 0.4 * ratio

            lineColorArr[lineIndex * 6]     = r
            lineColorArr[lineIndex * 6 + 1] = g
            lineColorArr[lineIndex * 6 + 2] = b
            lineColorArr[lineIndex * 6 + 3] = r
            lineColorArr[lineIndex * 6 + 4] = g
            lineColorArr[lineIndex * 6 + 5] = b

            lineIndex++
          }
        }
      }
      
      linesGeo.setDrawRange(0, lineIndex * 2)
      linesGeo.attributes.position.needsUpdate = true
      linesGeo.attributes.color.needsUpdate = true

      // Eased mouse interactivity
      points.rotation.y += (targetRotationY - points.rotation.y) * 0.04
      points.rotation.x += (targetRotationX - points.rotation.x) * 0.04
      lines.rotation.y = points.rotation.y
      lines.rotation.x = points.rotation.x

      // Tiny ambient rotation
      points.rotation.y += 0.0003
      lines.rotation.y += 0.0003

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
      window.removeEventListener('mousemove', onMouseMove)
      renderer.dispose()
      if (mount.contains(renderer.domElement)) mount.removeChild(renderer.domElement)
    }
  }, [])

  return (
    <div ref={mountRef} className="fixed inset-0 pointer-events-none z-0" />
  )
}
