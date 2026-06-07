import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Monitor, FileText, Search, Brain, Activity, Cpu, EyeOff, ShieldCheck,
  Play, ShieldAlert, Sparkles, Terminal, Info, RefreshCw
} from 'lucide-react'
import Header from '../components/layout/Header'
import { useWebSocket } from '../hooks/useWebSocket'

const NODES = [
  { id: 0, name: 'Client App', role: 'Request Source', icon: Monitor, x: 80, y: 200, desc: 'Initiates user interactions. Dispatches prompts and parameters to the secure agent gateway.' },
  { id: 1, name: 'Pattern Guard', role: 'Regex Scanner', icon: FileText, x: 220, y: 130, desc: 'Scans inputs against 60+ pre-compiled exploit signatures (Direct Injections, Jailbreak attempts).' },
  { id: 2, name: 'Semantic Guard', role: 'Heuristic Check', icon: Search, x: 360, y: 270, desc: 'Executes lightweight keyword list taxonomy evaluation and semantic context search to catch obfuscation.' },
  { id: 3, name: 'LLM Guard', role: 'Deep Analysis', icon: Brain, x: 500, y: 130, desc: 'Leverages high-performance LLM agent logic to run deep safety check analysis on complex prompts.' },
  { id: 4, name: 'Session Guard', role: 'Behavior Tracker', icon: Activity, x: 640, y: 270, desc: 'Monitors historical prompt patterns, rate limit compliance, and cumulative session threat escalation.' },
  { id: 5, name: 'Agent Core', role: 'Agent Logic', icon: Cpu, x: 780, y: 200, desc: 'Executes the core enterprise agent loop, including tool execution and Azure model generation.' },
  { id: 6, name: 'Output Guard', role: 'Leak Protection', icon: EyeOff, x: 920, y: 200, desc: 'Scans outgoing agent responses for credentials, secrets (API keys), and PII, redacting leaks in real time.' },
  { id: 7, name: 'Safe Response', role: 'Delivery Interface', icon: ShieldCheck, x: 1050, y: 200, desc: 'Transmits sanitized, validated, and redacted output payloads back to the client application.' },
]

export default function Pipeline() {
  const [simulationState, setSimulationState] = useState('idle') // 'idle' | 'clean' | 'attack' | 'leak' | 'websocket'
  const [activeStep, setActiveStep] = useState(-1)
  const [nodeStatuses, setNodeStatuses] = useState(Array(8).fill('idle')) // 'idle' | 'processing' | 'success' | 'failed' | 'warning' | 'redacted'
  const [selectedNode, setSelectedNode] = useState(0)
  const [liveLogs, setLiveLogs] = useState([
    { id: 1, timestamp: new Date().toLocaleTimeString(), text: 'Pipeline guard initialized. Standing by.', type: 'info' }
  ])
  const [animatingEvent, setAnimatingEvent] = useState(null)
  
  const logContainerRef = useRef(null)

  // Auto-scroll logs
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [liveLogs])

  const addLiveLog = (text, type = 'info') => {
    setLiveLogs(prev => [
      ...prev,
      {
        id: Date.now() + Math.random(),
        timestamp: new Date().toLocaleTimeString(),
        text,
        type
      }
    ].slice(-40)) // limit logs buffer
  }

  // WebSocket live updates
  const { connected } = useWebSocket((msg) => {
    if (simulationState !== 'idle') return // ignore during manual simulations

    if (msg.type === 'threat_event') {
      const isBlock = msg.action === 'block'
      const isWarn = msg.action === 'warn'
      
      addLiveLog(`[WebSocket Input] Session ${msg.session_id.slice(0, 8)}: ${msg.action.toUpperCase()} (Trust: ${msg.trust_score})`, isBlock ? 'error' : isWarn ? 'warning' : 'success')
      triggerRealTimeFlow(msg)
    } else if (msg.type === 'leak_event') {
      addLiveLog(`[WebSocket Output] Session ${msg.session_id?.slice(0, 8) || 'unknown'} detected leak: Redacted`, 'warning')
      triggerRealTimeLeakFlow(msg)
    }
  })

  // Animate real-time threat inputs
  const triggerRealTimeFlow = async (event) => {
    setSimulationState('websocket')
    setAnimatingEvent(event)
    
    const isBlock = event.action === 'block'
    const isWarn = event.action === 'warn'
    
    let blockStep = -1
    if (isBlock) {
      if (event.llm_used) {
        blockStep = 3 // LLM Guard
      } else if (event.pattern_matches && event.pattern_matches.length > 0) {
        blockStep = 1 // Pattern Guard
      } else {
        blockStep = 2 // Semantic Guard
      }
    } else if (isWarn) {
      blockStep = 4 // Session Guard warns
    }
    
    const steps = 8
    setNodeStatuses(Array(8).fill('idle'))
    
    for (let i = 0; i < steps; i++) {
      setActiveStep(i)
      setSelectedNode(i)
      setNodeStatuses(prev => {
        const next = [...prev]
        next[i] = 'processing'
        return next
      })
      
      await new Promise(r => setTimeout(r, 400))
      
      setNodeStatuses(prev => {
        const next = [...prev]
        if (i === blockStep) {
          next[i] = isBlock ? 'failed' : 'warning'
          return next
        }
        next[i] = 'success'
        return next
      })
      
      if (i === blockStep && isBlock) {
        addLiveLog(`[Real-time Guard Block] Request rejected by ${NODES[blockStep].name} due to security constraints.`, 'error')
        break
      }
    }
    
    setSimulationState('idle')
    setAnimatingEvent(null)
  }

  // Animate real-time leak outputs
  const triggerRealTimeLeakFlow = async (event) => {
    setSimulationState('websocket')
    setAnimatingEvent(event)
    
    const steps = 8
    setNodeStatuses(Array(8).fill('idle'))
    
    for (let i = 0; i < steps; i++) {
      setActiveStep(i)
      setSelectedNode(i)
      setNodeStatuses(prev => {
        const next = [...prev]
        next[i] = 'processing'
        return next
      })
      
      await new Promise(r => setTimeout(r, 400))
      
      setNodeStatuses(prev => {
        const next = [...prev]
        if (i === 6) { // Output Guard
          next[i] = 'redacted'
          return next
        }
        next[i] = 'success'
        return next
      })
      
      if (i === 6) {
        addLiveLog(`[Real-time Guard Redact] Sensitive contents scrubbed successfully at Output Guard.`, 'warning')
        break
      }
    }
    
    setSimulationState('idle')
    setAnimatingEvent(null)
  }

  // Manual Simulations
  const runSimulation = async (type) => {
    if (simulationState !== 'idle') return
    setSimulationState(type)
    
    const steps = 8
    const stepDelays = {
      clean: [250, 250, 250, 250, 250, 350, 250, 250],
      attack: [250, 250, 250, 300, 0, 0, 0, 0], // Blocked at LLM Guard
      leak: [250, 250, 250, 250, 250, 350, 350, 0] // Redacted at Output Guard
    }
    
    setNodeStatuses(Array(8).fill('idle'))
    addLiveLog(`[Simulation Started] Running scenario: ${type.toUpperCase()}`, 'info')

    for (let i = 0; i < steps; i++) {
      setActiveStep(i)
      setSelectedNode(i)
      setNodeStatuses(prev => {
        const next = [...prev]
        next[i] = 'processing'
        return next
      })
      
      await new Promise(resolve => setTimeout(resolve, stepDelays[type][i] || 250))
      
      setNodeStatuses(prev => {
        const next = [...prev]
        if (type === 'attack' && i === 3) {
          next[i] = 'failed'
          return next
        }
        if (type === 'leak' && i === 6) {
          next[i] = 'redacted'
          return next
        }
        next[i] = 'success'
        return next
      })
      
      if (type === 'attack' && i === 3) {
        addLiveLog(`[Shield Action] Request blocked at LLM Guard (Adversarial pattern detected).`, 'error')
        break
      }
      if (type === 'leak' && i === 6) {
        addLiveLog(`[Shield Action] Outgoing response redacted at Output Guard (AWS access key intercepted).`, 'warning')
        break
      }
    }
    
    if (type === 'clean') {
      addLiveLog(`[Shield Action] Request allowed. Clean response safely delivered.`, 'success')
    }
    
    setSimulationState('idle')
  }

  // Generate cubic bezier pathway for connecting curves
  const getBezierPath = (x1, y1, x2, y2) => {
    const dx = Math.abs(x2 - x1) * 0.5
    return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Dynamic inline styles for SVG flow animations */}
      <style>{`
        @keyframes strokeFlow {
          to {
            stroke-dashoffset: -20;
          }
        }
        .flowing-path {
          stroke-dasharray: 6 4;
          animation: strokeFlow 0.8s linear infinite;
        }
        .pulse-glow {
          box-shadow: 0 0 15px rgba(0, 113, 227, 0.4);
        }
        .terminal-scroll::-webkit-scrollbar {
          width: 4px;
        }
        .terminal-scroll::-webkit-scrollbar-thumb {
          background: rgba(255, 255, 255, 0.15);
          border-radius: 2px;
        }
      `}</style>

      <Header 
        title="Pipeline Guard Graph" 
        subtitle="Interactive request pathway inspection through safety filters"
      />

      <div className="flex-grow overflow-y-auto p-8 pb-12">
        <div className="max-w-[1400px] mx-auto grid grid-cols-1 xl:grid-cols-12 gap-8">
          
          {/* Left Panel: SVG Visualization */}
          <div className="xl:col-span-8 flex flex-col gap-6">
            <div className="card p-6 flex flex-col items-center justify-center relative overflow-hidden" style={{ minHeight: 450 }}>
              
              {/* Header inside visualization panel */}
              <div className="w-full flex items-center justify-between mb-4 z-10">
                <div className="flex items-center gap-2">
                  <div className={`live-dot ${connected ? 'bg-[#30d158]' : 'bg-[#ff9f0a]'}`} />
                  <span className="text-[11px] font-semibold text-[#86868b] tracking-wider uppercase">
                    {connected ? 'WS CONNECTED: RECEIVING REAL-TIME EVENTS' : 'WS CONNECTING...'}
                  </span>
                </div>
                {simulationState !== 'idle' && (
                  <div className="flex items-center gap-2 text-xs text-[#0071e3]">
                    <RefreshCw className="animate-spin" size={12} />
                    <span>Analyzing pipeline flow...</span>
                  </div>
                )}
              </div>

              {/* Responsive SVG container */}
              <div className="w-full overflow-x-auto overflow-y-hidden py-4">
                <svg viewBox="0 0 1150 400" className="w-[1150px] h-[360px] select-none block mx-auto">
                  {/* Grid background markers */}
                  <defs>
                    <radialGradient id="nodeGlow" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="#0071e3" stopOpacity="0.15" />
                      <stop offset="100%" stopColor="#0071e3" stopOpacity="0" />
                    </radialGradient>
                    <radialGradient id="dangerGlow" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="#ff453a" stopOpacity="0.2" />
                      <stop offset="100%" stopColor="#ff453a" stopOpacity="0" />
                    </radialGradient>
                    <radialGradient id="warningGlow" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="#ff9f0a" stopOpacity="0.2" />
                      <stop offset="100%" stopColor="#ff9f0a" stopOpacity="0" />
                    </radialGradient>
                  </defs>

                  {/* Bezier links */}
                  {NODES.slice(0, -1).map((node, index) => {
                    const nextNode = NODES[index + 1]
                    const isActive = activeStep >= index && activeStep <= index + 1
                    
                    // Determine color based on pathway states
                    let strokeColor = 'rgba(255, 255, 255, 0.06)'
                    let flowClass = ''
                    
                    if (isActive && simulationState !== 'idle') {
                      flowClass = 'flowing-path'
                      
                      // Highlight color
                      const currentStatus = nodeStatuses[index + 1]
                      if (currentStatus === 'failed') {
                        strokeColor = '#ff453a'
                      } else if (currentStatus === 'warning' || currentStatus === 'redacted') {
                        strokeColor = '#ff9f0a'
                      } else {
                        strokeColor = '#0071e3'
                      }
                    } else if (activeStep > index) {
                      // Already passed
                      const nextStatus = nodeStatuses[index + 1]
                      if (nextStatus === 'failed') strokeColor = 'rgba(255, 69, 58, 0.2)'
                      else if (nextStatus === 'warning' || nextStatus === 'redacted') strokeColor = 'rgba(255, 159, 10, 0.2)'
                      else strokeColor = 'rgba(48, 209, 88, 0.25)'
                    }

                    return (
                      <path
                        key={`edge-${index}`}
                        d={getBezierPath(node.x, node.y, nextNode.x, nextNode.y)}
                        fill="none"
                        stroke={strokeColor}
                        strokeWidth={isActive ? 2.5 : 1.5}
                        className={flowClass}
                      />
                    )
                  })}

                  {/* Render node circles */}
                  {NODES.map((node, index) => {
                    const Icon = node.icon
                    const status = nodeStatuses[index]
                    const isSelected = selectedNode === index
                    
                    // Status colors
                    let strokeColor = 'rgba(255, 255, 255, 0.08)'
                    let fillColor = 'rgba(15, 15, 15, 0.9)'
                    let iconColor = '#86868b'
                    let glow = null

                    if (status === 'processing') {
                      strokeColor = '#0071e3'
                      iconColor = '#0071e3'
                      glow = <circle cx={node.x} cy={node.y} r={45} fill="url(#nodeGlow)" />
                    } else if (status === 'success') {
                      strokeColor = '#30d158'
                      iconColor = '#30d158'
                    } else if (status === 'failed') {
                      strokeColor = '#ff453a'
                      iconColor = '#ff453a'
                      glow = <circle cx={node.x} cy={node.y} r={45} fill="url(#dangerGlow)" />
                    } else if (status === 'warning' || status === 'redacted') {
                      strokeColor = '#ff9f0a'
                      iconColor = '#ff9f0a'
                      glow = <circle cx={node.x} cy={node.y} r={45} fill="url(#warningGlow)" />
                    }

                    if (isSelected) {
                      strokeColor = strokeColor === 'rgba(255, 255, 255, 0.08)' ? '#f5f5f7' : strokeColor
                    }

                    return (
                      <g 
                        key={node.id} 
                        onClick={() => setSelectedNode(index)}
                        style={{ cursor: 'pointer' }}
                        className="group"
                      >
                        {/* Glow effect */}
                        {glow}

                        {/* Outer hover ring */}
                        <circle
                          cx={node.x}
                          cy={node.y}
                          r={28}
                          fill="transparent"
                          stroke={isSelected ? '#0071e3' : 'transparent'}
                          strokeWidth={1.5}
                          className="transition-all duration-300 group-hover:stroke-[rgba(255,255,255,0.2)]"
                        />

                        {/* Node circle */}
                        <circle
                          cx={node.x}
                          cy={node.y}
                          r={22}
                          fill={fillColor}
                          stroke={strokeColor}
                          strokeWidth={isSelected ? 2 : 1.5}
                          className="transition-all duration-300"
                        />

                        {/* Icon */}
                        <g transform={`translate(${node.x - 9}, ${node.y - 9})`}>
                          <Icon size={18} color={iconColor} className="transition-all duration-300" />
                        </g>

                        {/* Label */}
                        <text
                          x={node.x}
                          y={node.y + 40}
                          textAnchor="middle"
                          fill={isSelected ? '#ffffff' : '#86868b'}
                          fontSize={10.5}
                          fontWeight={isSelected ? 600 : 500}
                          className="transition-all duration-300 font-sans"
                        >
                          {node.name}
                        </text>
                      </g>
                    )
                  })}
                </svg>
              </div>
            </div>

            {/* Simulated request visualization card */}
            <div className="card p-6">
              <div className="flex items-center gap-2.5 mb-4">
                <Terminal size={16} className="text-[#0071e3]" />
                <h3 className="text-sm font-semibold text-[#f5f5f7] tracking-tight">Active Pipeline Logs</h3>
              </div>
              <div 
                ref={logContainerRef}
                className="terminal-scroll font-mono text-xs overflow-y-auto space-y-2.5 p-4 rounded-xl"
                style={{ 
                  height: 180, 
                  background: 'rgba(5, 5, 5, 0.75)', 
                  border: '1px solid rgba(255, 255, 255, 0.05)'
                }}
              >
                {liveLogs.map((log) => {
                  let color = '#86868b'
                  if (log.type === 'error') color = '#ff453a'
                  else if (log.type === 'warning') color = '#ff9f0a'
                  else if (log.type === 'success') color = '#30d158'
                  
                  return (
                    <div key={log.id} style={{ color }} className="leading-5">
                      <span className="text-[#6e6e73] mr-2">[{log.timestamp}]</span>
                      <span>{log.text}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Right Panel: Controls & Details */}
          <div className="xl:col-span-4 flex flex-col gap-6">
            
            {/* Simulation controls */}
            <div className="card p-6">
              <div className="flex items-center gap-2 mb-4">
                <Play size={15} className="text-[#30d158]" />
                <h3 className="text-sm font-semibold text-[#f5f5f7]">Simulation Controls</h3>
              </div>
              
              <p className="text-xs text-[#86868b] leading-relaxed mb-6 font-light">
                Trigger mock events manually to test how inputs are scanned, deep analyzed, and outputs are redacted instantly.
              </p>

              <div className="space-y-3">
                <button
                  disabled={simulationState !== 'idle'}
                  onClick={() => runSimulation('clean')}
                  className="btn btn-secondary w-full justify-between hover:border-[#30d158]/30 hover:bg-[#30d158]/5 group"
                >
                  <span className="flex items-center gap-2 font-medium">
                    <Sparkles size={14} className="text-[#30d158]" />
                    Safe Prompt Request
                  </span>
                  <span className="text-[10px] text-[#6e6e73] font-mono group-hover:text-[#30d158]">PASS</span>
                </button>

                <button
                  disabled={simulationState !== 'idle'}
                  onClick={() => runSimulation('attack')}
                  className="btn btn-secondary w-full justify-between hover:border-[#ff453a]/30 hover:bg-[#ff453a]/5 group"
                >
                  <span className="flex items-center gap-2 font-medium">
                    <ShieldAlert size={14} className="text-[#ff453a]" />
                    Adversarial Prompt Attack
                  </span>
                  <span className="text-[10px] text-[#6e6e73] font-mono group-hover:text-[#ff453a]">BLOCK</span>
                </button>

                <button
                  disabled={simulationState !== 'idle'}
                  onClick={() => runSimulation('leak')}
                  className="btn btn-secondary w-full justify-between hover:border-[#ff9f0a]/30 hover:bg-[#ff9f0a]/5 group"
                >
                  <span className="flex items-center gap-2 font-medium">
                    <EyeOff size={14} className="text-[#ff9f0a]" />
                    Sensitive Data Output Leak
                  </span>
                  <span className="text-[10px] text-[#6e6e73] font-mono group-hover:text-[#ff9f0a]">REDACT</span>
                </button>
              </div>
            </div>

            {/* Inspector */}
            <div className="card p-6 flex-grow flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 mb-4">
                  <Info size={15} className="text-[#0071e3]" />
                  <h3 className="text-sm font-semibold text-[#f5f5f7]">Guard Inspector</h3>
                </div>

                <AnimatePresence mode="wait">
                  {selectedNode !== null ? (
                    <motion.div
                      key={selectedNode}
                      initial={{ opacity: 0, y: 5 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -5 }}
                      transition={{ duration: 0.2 }}
                      className="space-y-6"
                    >
                      <div>
                        <div className="text-xs text-[#86868b] tracking-wider uppercase font-semibold font-sans">{NODES[selectedNode].role}</div>
                        <h4 className="text-lg font-bold text-[#ffffff] mt-1 font-sans">{NODES[selectedNode].name}</h4>
                      </div>

                      <div className="divider" />

                      <div className="space-y-4">
                        <div>
                          <div className="text-[10px] text-[#86868b] tracking-wider uppercase font-bold">Latency Overhead</div>
                          <div className="text-sm font-semibold text-[#f5f5f7] mt-1 font-mono">
                            {selectedNode === 0 || selectedNode === 7 ? '0 ms (Pass)' : 
                             selectedNode === 1 ? '1.5 ms' :
                             selectedNode === 2 ? '11.8 ms' :
                             selectedNode === 3 ? '184 ms (LLM)' :
                             selectedNode === 4 ? '1.2 ms' :
                             selectedNode === 5 ? '420 ms (Azure OpenAI)' :
                             '8.2 ms'}
                          </div>
                        </div>

                        <div>
                          <div className="text-[10px] text-[#86868b] tracking-wider uppercase font-bold">Throughput Capacity</div>
                          <div className="text-sm font-semibold text-[#30d158] mt-1 font-mono">100% Operational</div>
                        </div>

                        <div>
                          <div className="text-[10px] text-[#86868b] tracking-wider uppercase font-bold">Function Description</div>
                          <p className="text-xs text-[#86868b] leading-relaxed mt-2 font-light">
                            {NODES[selectedNode].desc}
                          </p>
                        </div>
                      </div>
                    </motion.div>
                  ) : (
                    <div className="text-center py-12 text-xs text-[#86868b]">
                      Select a node in the graph to inspect metrics and operational configurations.
                    </div>
                  )}
                </AnimatePresence>
              </div>

              {animatingEvent && (
                <div 
                  className="mt-6 p-4 rounded-xl border border-dashed border-[#0071e3]/30 bg-[#0071e3]/5 text-xs text-left"
                >
                  <div className="font-semibold text-[#f5f5f7] mb-1">Incoming Real-time Event</div>
                  <div className="text-[#86868b] font-mono overflow-hidden text-ellipsis whitespace-nowrap mb-1">
                    ID: {animatingEvent.session_id}
                  </div>
                  <div className="text-[#86868b]">
                    Category: <span className="text-[#f5f5f7]">{animatingEvent.threat_category || 'Leak Detection'}</span>
                  </div>
                </div>
              )}
            </div>

          </div>

        </div>
      </div>
    </div>
  )
}
