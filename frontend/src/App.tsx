import { useState, useEffect } from 'react';
import { 
  ShieldAlert, Activity, Rss, FileText, Binary, 
  Database, Bell, Settings, RefreshCw, ExternalLink, 
  Search, Terminal, Download, Mail, Zap, Calendar,
  Crosshair, X
} from 'lucide-react';
import type { 
  DashboardSummary, IncidentSummary, IncidentDetail, 
  IOCItem, SourceItem, NotificationItem, AgentRunItem,
  DayWiseGroup, IOAItem, SearchResults
} from './types';

const API_BASE = "http://localhost:8000/api";

export function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'agents' | 'feed' | 'daywise' | 'detail' | 'iocs' | 'ioas' | 'knowledge' | 'notifications' | 'settings'>('overview');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  
  // Data State
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [dayGroups, setDayGroups] = useState<DayWiseGroup[]>([]);
  const [incidentDetail, setIncidentDetail] = useState<IncidentDetail | null>(null);
  const [agentRuns, setAgentRuns] = useState<AgentRunItem[]>([]);
  const [iocs, setIocs] = useState<IOCItem[]>([]);
  const [ioas, setIoas] = useState<IOAItem[]>([]);
  const [sources, setSources] = useState<SourceItem[]>([]);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  
  // Global Unified Search State
  const [globalQuery, setGlobalQuery] = useState("");
  const [globalSearchResults, setGlobalSearchResults] = useState<SearchResults | null>(null);
  const [isGlobalSearching, setIsGlobalSearching] = useState(false);
  const [showSearchModal, setShowSearchModal] = useState(false);

  // Knowledge & RAG State
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [uploadTitle, setUploadTitle] = useState("");
  const [uploadContent, setUploadContent] = useState("");
  const [uploadSourceUrl, setUploadSourceUrl] = useState("");

  // Loading & Actions
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchDashboardData = async () => {
    try {
      const [sumRes, incRes, dayRes] = await Promise.all([
        fetch(`${API_BASE}/dashboard/summary`).then(r => r.json()),
        fetch(`${API_BASE}/incidents`).then(r => r.json()),
        fetch(`${API_BASE}/incidents/day-wise`).then(r => r.json())
      ]);
      setSummary(sumRes);
      setIncidents(incRes);
      setDayGroups(dayRes);
    } catch (e) {
      console.error("Failed fetching dashboard data", e);
    }
  };

  const fetchDayWise = async () => {
    try {
      const res = await fetch(`${API_BASE}/incidents/day-wise`).then(r => r.json());
      setDayGroups(res);
    } catch (e) {
      console.error("Failed fetching day-wise data", e);
    }
  };

  const fetchIoas = async () => {
    try {
      const res = await fetch(`${API_BASE}/ioas`).then(r => r.json());
      setIoas(res);
    } catch (e) {
      console.error("Failed fetching IOAs", e);
    }
  };

  const fetchAgentRuns = async () => {
    try {
      const res = await fetch(`${API_BASE}/agents/runs`).then(r => r.json());
      setAgentRuns(res);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchIocs = async () => {
    try {
      const res = await fetch(`${API_BASE}/iocs`).then(r => r.json());
      setIocs(res);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchSources = async () => {
    try {
      const res = await fetch(`${API_BASE}/sources`).then(r => r.json());
      setSources(res);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchNotifications = async () => {
    try {
      const res = await fetch(`${API_BASE}/notifications`).then(r => r.json());
      setNotifications(res);
    } catch (e) {
      console.error(e);
    }
  };

  const loadIncidentDetail = async (id: string) => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/incidents/${id}`).then(r => r.json());
      setIncidentDetail(res);
      setSelectedIncidentId(id);
      setActiveTab('detail');
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const triggerLiveInvestigation = async (id: string) => {
    setLoading(true);
    setActionMessage("Swarm orchestrator dispatched agents for investigation...");
    try {
      const res = await fetch(`${API_BASE}/incidents/${id}/investigate`, { method: "POST" }).then(r => r.json());
      setActionMessage(`Investigation complete! Status: ${res.status}`);
      await fetchDashboardData();
      await loadIncidentDetail(id);
    } catch (e) {
      setActionMessage(`Investigation failed: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  const triggerScheduledSweep = async () => {
    setLoading(true);
    setActionMessage("Executing full automated sweep across CISA, THN, BleepingComputer & SANS ISC with auto-research...");
    try {
      const res = await fetch(`${API_BASE}/scheduler/sweep`, { method: "POST" }).then(r => r.json());
      setActionMessage(`Sweep completed: ${res.new_documents} sources fetched, ${res.new_incidents} incidents auto-analyzed by Swarm!`);
      await fetchDashboardData();
      await fetchDayWise();
      await fetchIoas();
      await fetchNotifications();
    } catch (e) {
      setActionMessage(`Sweep error: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  const handleGlobalSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!globalQuery.trim()) return;
    setIsGlobalSearching(true);
    setShowSearchModal(true);
    try {
      const res = await fetch(`${API_BASE}/search?q=${encodeURIComponent(globalQuery)}`).then(r => r.json());
      setGlobalSearchResults(res);
    } catch (err) {
      console.error("Global search failed:", err);
    } finally {
      setIsGlobalSearching(false);
    }
  };

  const sendTestNotification = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/notifications/test`, { 
        method: "POST", 
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recipient: "security-analyst@example.com" })
      }).then(r => r.json());
      setActionMessage(`Test notification dispatched: ${res.send_result.status}. Check Notification Center for HTML preview.`);
      await fetchNotifications();
    } catch (e) {
      setActionMessage(`Test notification failed: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  const handleKnowledgeSearch = async () => {
    if (!searchQuery.trim()) return;
    setIsSearching(true);
    try {
      const res = await fetch(`${API_BASE}/knowledge/search?q=${encodeURIComponent(searchQuery)}`).then(r => r.json());
      setSearchResults(res.results || []);
    } catch (e) {
      console.error(e);
    } finally {
      setIsSearching(false);
    }
  };

  const handleUploadDocument = async () => {
    if (!uploadTitle.trim() || !uploadContent.trim()) return;
    setLoading(true);
    try {
      await fetch(`${API_BASE}/knowledge/documents`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: uploadTitle,
          content: uploadContent,
          source_url: uploadSourceUrl
        })
      });
      setActionMessage(`Knowledge document "${uploadTitle}" successfully indexed into vector store!`);
      setUploadTitle("");
      setUploadContent("");
      setUploadSourceUrl("");
      await fetchDashboardData();
    } catch (e) {
      setActionMessage(`Upload failed: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  const exportIOCs = (format: 'json' | 'csv') => {
    let dataStr = "";
    if (format === 'json') {
      dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(iocs, null, 2));
    } else {
      const headers = "id,type,value,defanged,threat_status,first_seen\n";
      const rows = iocs.map(i => `"${i.id}","${i.type}","${i.value}","${i.defanged}","${i.threat_status}","${i.first_seen}"`).join("\n");
      dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(headers + rows);
    }
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `soc_swarm_iocs.${format}`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportIOAs = (format: 'json' | 'csv') => {
    let dataStr = "";
    if (format === 'json') {
      dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(ioas, null, 2));
    } else {
      const headers = "id,type,pattern_name,technique_id,observed_behavior,detection_logic,confidence\n";
      const rows = ioas.map(i => `"${i.id}","${i.type}","${i.pattern_name.replace(/"/g, '""')}","${i.technique_id || ''}","${i.observed_behavior.replace(/"/g, '""')}","${i.detection_logic.replace(/"/g, '""')}","${i.confidence || 0.9}"`).join("\n");
      dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(headers + rows);
    }
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `soc_swarm_ioas.${format}`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (activeTab === 'agents') fetchAgentRuns();
    if (activeTab === 'daywise') fetchDayWise();
    if (activeTab === 'iocs') fetchIocs();
    if (activeTab === 'ioas') fetchIoas();
    if (activeTab === 'feed') fetchSources();
    if (activeTab === 'notifications') fetchNotifications();
  }, [activeTab]);

  return (
    <div className="flex h-screen bg-[#090d16] text-slate-100 font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-800 bg-[#0c1220] flex flex-col justify-between">
        <div>
          <div className="p-5 border-b border-slate-800 flex items-center space-x-3">
            <div className="bg-sky-500/10 border border-sky-500/30 p-2 rounded-lg text-sky-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-bold text-sm tracking-wide text-white">SOC SWARM CTI</h1>
              <p className="text-[11px] text-sky-400 font-mono">AUTONOMOUS MULTI-AGENT</p>
            </div>
          </div>

          <nav className="p-3 space-y-1">
            {[
              { id: 'overview', label: 'Dashboard Overview', icon: Activity },
              { id: 'daywise', label: 'Day-Wise Threat Reports', icon: Calendar },
              { id: 'agents', label: 'Live Agent Swarm', icon: Terminal },
              { id: 'feed', label: 'Threat Intel Feed', icon: Rss },
              { id: 'detail', label: 'Incident Detail', icon: FileText, disabled: !selectedIncidentId },
              { id: 'iocs', label: 'IOC Explorer', icon: Binary },
              { id: 'ioas', label: 'IOA Explorer (Attacks)', icon: Crosshair },
              { id: 'knowledge', label: 'Knowledge & RAG', icon: Database },
              { id: 'notifications', label: 'Notification Center', icon: Bell },
              { id: 'settings', label: 'Settings & Config', icon: Settings },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  disabled={tab.disabled}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                    isActive 
                      ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30' 
                      : tab.disabled 
                        ? 'opacity-40 cursor-not-allowed text-slate-500'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* System telemetry footer */}
        <div className="p-4 border-t border-slate-800 text-[11px] text-slate-400 space-y-2 bg-[#0a0e17]">
          <div className="flex items-center justify-between">
            <span>Model:</span>
            <span className="text-sky-400 font-mono">Gemini 3.8 Flash</span>
          </div>
          <div className="flex items-center justify-between">
            <span>RAG Engine:</span>
            <span className="text-emerald-400 font-mono">text-embedding-004</span>
          </div>
          <div className="flex items-center justify-between">
            <span>Gmail Mode:</span>
            <span className="text-amber-400 font-mono">{summary?.gmail_status || 'preview'}</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-hidden bg-[#090d16]">
        {/* Top Header */}
        <header className="h-14 border-b border-slate-800 bg-[#0c1220]/60 px-6 flex items-center justify-between backdrop-blur">
          <div className="flex items-center space-x-4 flex-1">
            <span className="text-xs font-medium text-slate-400 hidden xl:inline">
              Workspace: <strong className="text-white">qwiklabs-gcp-03-fd05546dff54</strong>
            </span>

            {/* Global Search Bar */}
            <form onSubmit={handleGlobalSearch} className="flex-1 max-w-md relative">
              <input
                type="text"
                value={globalQuery}
                onChange={(e) => setGlobalQuery(e.target.value)}
                placeholder="Global search reports, CVEs, IOCs, or behavioral IOAs..."
                className="w-full bg-[#090d16] border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 placeholder:text-slate-500"
              />
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            </form>

            {actionMessage && (
              <span className="text-xs bg-sky-950/70 border border-sky-800/50 text-sky-300 px-3 py-1 rounded-full animate-pulse truncate max-w-xs">
                {actionMessage}
              </span>
            )}
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={triggerScheduledSweep}
              disabled={loading}
              title="Runs on-demand sweep across CISA, THN, BleepingComputer, SANS ISC and triggers Swarm research"
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-gradient-to-r from-amber-600 to-rose-600 hover:from-amber-500 hover:to-rose-500 text-white rounded text-xs font-semibold transition shadow-sm"
            >
              <Zap className={`w-3.5 h-3.5 ${loading ? 'animate-bounce' : ''}`} />
              <span>Sweep All Feeds & Research</span>
            </button>
            <button
              onClick={sendTestNotification}
              disabled={loading}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition border border-slate-700"
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Test Gmail Alert</span>
            </button>
          </div>
        </header>

        {/* Viewport */}
        <div className="flex-1 overflow-y-auto p-6">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              {/* Stat Cards */}
              <div className="grid grid-cols-5 gap-4">
                <div className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl">
                  <span className="text-xs text-slate-400 font-medium">Discovered Incidents</span>
                  <div className="text-2xl font-bold text-white mt-1">{summary?.total_incidents_discovered || 0}</div>
                  <span className="text-[11px] text-sky-400 mt-2 block">Live CISA, THN, BC, SANS</span>
                </div>
                <div className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl">
                  <span className="text-xs text-slate-400 font-medium">Fully Investigated</span>
                  <div className="text-2xl font-bold text-emerald-400 mt-1">{summary?.incidents_investigated || 0}</div>
                  <span className="text-[11px] text-slate-400 mt-2 block">Swarm verified findings</span>
                </div>
                <div className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl">
                  <span className="text-xs text-slate-400 font-medium">Extracted IOCs</span>
                  <div className="text-2xl font-bold text-amber-400 mt-1">{summary?.total_iocs_extracted || 0}</div>
                  <span className="text-[11px] text-slate-400 mt-2 block">Hashes, IPs, Domains, CVEs</span>
                </div>
                <div className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl">
                  <span className="text-xs text-slate-400 font-medium">Extracted IOAs</span>
                  <div className="text-2xl font-bold text-purple-400 mt-1">{summary?.total_ioas_extracted || 0}</div>
                  <span className="text-[11px] text-purple-400 mt-2 block">Adversary Behavioral Patterns</span>
                </div>
                <div className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl">
                  <span className="text-xs text-slate-400 font-medium">High / Critical Threats</span>
                  <div className="text-2xl font-bold text-rose-400 mt-1">{summary?.high_severity_incidents || 0}</div>
                  <span className="text-[11px] text-rose-400 mt-2 block">Priority Action Required</span>
                </div>
              </div>

              {/* Recent Incident Feed Table */}
              <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden">
                <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-semibold text-white">Latest Discovered & Investigated Incidents</h2>
                    <p className="text-xs text-slate-400">Continuous monitoring stream from public disclosures and CISA feeds</p>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#0c1220] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                      <tr>
                        <th className="py-3 px-4">Severity</th>
                        <th className="py-3 px-4">Incident Title</th>
                        <th className="py-3 px-4">Affected Org</th>
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Confidence</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {incidents.map((inc) => (
                        <tr key={inc.id} className="hover:bg-slate-800/30 transition">
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              inc.severity === 'CRITICAL' ? 'bg-rose-950 border border-rose-800 text-rose-300' :
                              inc.severity === 'HIGH' ? 'bg-amber-950 border border-amber-800 text-amber-300' :
                              'bg-sky-950 border border-sky-800 text-sky-300'
                            }`}>
                              {inc.severity}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-sans font-medium text-slate-200 max-w-md truncate">
                            {inc.title}
                          </td>
                          <td className="py-3 px-4 text-slate-400 font-sans">
                            {inc.affected_organization || "Undisclosed"}
                          </td>
                          <td className="py-3 px-4">
                            <span className="text-[11px] px-2 py-0.5 bg-slate-800 rounded text-slate-300">
                              {inc.status}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-slate-400">
                            {(inc.confidence_score * 100).toFixed(0)}%
                          </td>
                          <td className="py-3 px-4 text-right space-x-2 font-sans">
                            {inc.status === 'DISCOVERED' ? (
                              <button
                                onClick={() => triggerLiveInvestigation(inc.id)}
                                className="px-2.5 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs transition"
                              >
                                Investigate
                              </button>
                            ) : (
                              <button
                                onClick={() => loadIncidentDetail(inc.id)}
                                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded text-xs transition"
                              >
                                View Report
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: LIVE AGENTS SWARM */}
          {activeTab === 'agents' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white">SOC Swarm Agent Executions</h2>
                  <p className="text-xs text-slate-400">Traceable multi-agent telemetry and decision rationales</p>
                </div>
                <button 
                  onClick={fetchAgentRuns} 
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs rounded border border-slate-700 text-slate-300"
                >
                  Refresh Traces
                </button>
              </div>

              <div className="space-y-3">
                {agentRuns.map((run) => (
                  <div key={run.id} className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl flex items-start justify-between">
                    <div className="space-y-1 max-w-3xl">
                      <div className="flex items-center space-x-3">
                        <span className="font-semibold text-sm text-sky-400">{run.agent_name}</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                          run.status === 'COMPLETED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                          'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}>
                          {run.status}
                        </span>
                        <span className="text-xs text-slate-500 font-mono">
                          {run.started_at ? new Date(run.started_at).toLocaleTimeString() : ''}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 font-sans">
                        {run.decision_summary || "Agent task executed successfully without exceptions."}
                      </p>
                    </div>
                    <div className="text-right text-xs text-slate-400 font-mono">
                      <span>{run.duration_seconds.toFixed(2)}s runtime</span>
                    </div>
                  </div>
                ))}
                {agentRuns.length === 0 && (
                  <div className="text-center py-12 text-slate-500 text-xs">
                    No recent agent runs recorded. Trigger an incident investigation to observe swarm execution.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB: DAY-WISE THREAT REPORTS */}
          {activeTab === 'daywise' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white">Day-Wise Threat Intelligence Reports</h2>
                  <p className="text-xs text-slate-400">Chronological calendar groupings of public advisories, TTPs, and IOCs</p>
                </div>
                <button
                  onClick={fetchDayWise}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs rounded border border-slate-700 text-slate-300 flex items-center space-x-1.5"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Refresh Days</span>
                </button>
              </div>

              {dayGroups.length === 0 ? (
                <div className="bg-[#0f172a] border border-slate-800 p-8 rounded-xl text-center text-xs text-slate-400">
                  No threat reports logged yet. Trigger a sweep above to ingest from all sources.
                </div>
              ) : (
                <div className="space-y-6">
                  {dayGroups.map((group) => (
                    <div key={group.date} className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden">
                      {/* Day Header Banner */}
                      <div className="p-4 bg-[#0c1220] border-b border-slate-800 flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="p-2 bg-sky-950/60 border border-sky-800/60 rounded-lg text-sky-400">
                            <Calendar className="w-4 h-4" />
                          </div>
                          <div>
                            <h3 className="text-sm font-bold text-white">{group.display_label}</h3>
                            <span className="text-[11px] font-mono text-slate-400">{group.date}</span>
                          </div>
                        </div>

                        <div className="flex items-center space-x-4 text-xs font-mono">
                          <span className="px-2.5 py-1 bg-slate-800 rounded text-slate-300">
                            {group.total_reports} {group.total_reports === 1 ? 'Report' : 'Reports'}
                          </span>
                          <span className="px-2.5 py-1 bg-amber-950/70 border border-amber-800/60 text-amber-300 rounded">
                            {group.total_iocs} IOCs
                          </span>
                          <span className="px-2.5 py-1 bg-purple-950/70 border border-purple-800/60 text-purple-300 rounded">
                            {group.total_ioas} IOAs
                          </span>
                          {group.high_critical_count > 0 && (
                            <span className="px-2.5 py-1 bg-rose-950/70 border border-rose-800/60 text-rose-300 rounded font-bold">
                              {group.high_critical_count} High/Crit
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Day's Reports List */}
                      <div className="divide-y divide-slate-800/60">
                        {group.reports.map((report) => (
                          <div key={report.id} className="p-4 hover:bg-slate-800/20 transition flex items-center justify-between">
                            <div className="space-y-1.5 max-w-4xl">
                              <div className="flex items-center space-x-2.5">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  report.severity === 'CRITICAL' ? 'bg-rose-950 border border-rose-800 text-rose-300' :
                                  report.severity === 'HIGH' ? 'bg-amber-950 border border-amber-800 text-amber-300' :
                                  'bg-sky-950 border border-sky-800 text-sky-300'
                                }`}>
                                  {report.severity}
                                </span>
                                <span className="font-semibold text-xs text-white">{report.title}</span>
                                <span className="text-[10px] text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded">
                                  {report.status}
                                </span>
                              </div>
                              <p className="text-xs text-slate-400 line-clamp-1">{report.summary}</p>
                              <div className="flex items-center space-x-3 text-[11px] text-slate-500 font-mono">
                                <span>Target: {report.affected_organization || 'Undisclosed'}</span>
                                <span>•</span>
                                <span>{report.iocs_count} IOCs</span>
                                <span>•</span>
                                <span>{report.ioas_count || 0} IOAs</span>
                                <span>•</span>
                                <span>{report.techniques_count} Techniques</span>
                              </div>
                            </div>

                            <div className="flex items-center space-x-2">
                              {report.status === 'DISCOVERED' ? (
                                <button
                                  onClick={() => triggerLiveInvestigation(report.id)}
                                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs transition font-semibold"
                                >
                                  Investigate
                                </button>
                              ) : (
                                <button
                                  onClick={() => loadIncidentDetail(report.id)}
                                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded text-xs transition border border-slate-700 font-semibold"
                                >
                                  View Analysis
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: THREAT INTEL FEED */}
          {activeTab === 'feed' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl">
                <h3 className="text-sm font-semibold text-white mb-2">Active Intelligence Ingestion Sources</h3>
                <div className="grid grid-cols-2 gap-4">
                  {sources.map(src => (
                    <div key={src.id} className="bg-[#0c1220] border border-slate-800/80 p-3 rounded-lg flex items-center justify-between">
                      <div>
                        <div className="text-xs font-semibold text-slate-200">{src.name}</div>
                        <div className="text-[11px] text-sky-400 font-mono truncate max-w-xs">{src.url}</div>
                      </div>
                      <span className="px-2 py-0.5 bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] rounded">
                        ENABLED
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden">
                <div className="p-4 border-b border-slate-800">
                  <h3 className="text-sm font-semibold text-white">Discovered Feeds & Articles</h3>
                </div>
                <div className="p-4 space-y-3">
                  {incidents.map(inc => (
                    <div key={inc.id} className="p-3 bg-[#0c1220] border border-slate-800/60 rounded-lg flex items-center justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                            inc.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300' : 'bg-slate-800 text-slate-300'
                          }`}>
                            {inc.severity}
                          </span>
                          <span className="text-xs font-medium text-white">{inc.title}</span>
                        </div>
                        <p className="text-xs text-slate-400 line-clamp-1">{inc.summary}</p>
                      </div>
                      <button
                        onClick={() => {
                          if (inc.status === 'DISCOVERED') triggerLiveInvestigation(inc.id);
                          else loadIncidentDetail(inc.id);
                        }}
                        className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs transition"
                      >
                        {inc.status === 'DISCOVERED' ? 'Run Swarm' : 'View Findings'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: INCIDENT DETAIL */}
          {activeTab === 'detail' && incidentDetail && (
            <div className="space-y-6 max-w-6xl mx-auto">
              <div className="bg-[#0f172a] border border-slate-800 p-6 rounded-xl space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-3">
                      <span className="px-2.5 py-0.5 bg-rose-950 text-rose-400 border border-rose-800 font-bold text-xs rounded">
                        {incidentDetail.severity}
                      </span>
                      <span className="text-xs text-slate-400">Target: <strong className="text-white">{incidentDetail.affected_organization || "Undisclosed"}</strong></span>
                      <span className="text-xs text-slate-400">Confidence: <strong className="text-sky-400">{(incidentDetail.confidence_score * 100).toFixed(0)}%</strong></span>
                    </div>
                    <h1 className="text-xl font-bold text-white mt-1">{incidentDetail.title}</h1>
                  </div>
                  {incidentDetail.source?.url && (
                    <a
                      href={incidentDetail.source.url}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center space-x-1 text-xs text-sky-400 hover:text-sky-300 bg-sky-950/40 border border-sky-800/40 px-3 py-1.5 rounded"
                    >
                      <span>Verified Source</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-6 text-xs">
                  <div className="space-y-2">
                    <h3 className="font-semibold text-sky-400 uppercase tracking-wider">Executive Summary</h3>
                    <p className="text-slate-300 leading-relaxed bg-[#0c1220] p-3 rounded-lg border border-slate-800">
                      {incidentDetail.summary}
                    </p>
                  </div>
                  <div className="space-y-2">
                    <h3 className="font-semibold text-rose-400 uppercase tracking-wider">Root Cause & Initial Access</h3>
                    <div className="text-slate-300 leading-relaxed bg-[#0c1220] p-3 rounded-lg border border-slate-800 space-y-2">
                      <p><strong>Initial Access:</strong> {incidentDetail.initial_access_vector || "Under investigation"}</p>
                      <p><strong>Root Cause:</strong> {incidentDetail.root_cause_analysis || "Awaiting evidence"}</p>
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK */}
                <div className="space-y-2 pt-2">
                  <h3 className="font-semibold text-xs text-slate-300 uppercase tracking-wider">MITRE ATT&CK Mappings</h3>
                  <div className="grid grid-cols-3 gap-3">
                    {incidentDetail.techniques.map((t, idx) => (
                      <div key={idx} className="bg-[#0c1220] border border-slate-800 p-3 rounded-lg space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs text-sky-400 font-bold">{t.id}</span>
                          <span className="text-[10px] px-1.5 py-0.5 bg-slate-800 text-slate-300 rounded">{t.tactic}</span>
                        </div>
                        <div className="text-xs font-semibold text-white">{t.name}</div>
                        <p className="text-[11px] text-slate-400 line-clamp-2">{t.supporting_behavior}</p>
                      </div>
                    ))}
                    {incidentDetail.techniques.length === 0 && (
                      <p className="text-xs text-slate-500 col-span-3">No ATT&CK techniques mapped for this advisory.</p>
                    )}
                  </div>
                </div>

                {/* Extracted IOCs */}
                <div className="space-y-2 pt-2">
                  <h3 className="font-semibold text-xs text-slate-300 uppercase tracking-wider">Extracted Indicators of Compromise (Defanged)</h3>
                  <div className="overflow-x-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#0c1220] text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="py-2 px-3">Type</th>
                          <th className="py-2 px-3">Safe Value</th>
                          <th className="py-2 px-3">Role / Context</th>
                          <th className="py-2 px-3">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 bg-[#0f172a]">
                        {incidentDetail.iocs.map((ioc, idx) => (
                          <tr key={idx}>
                            <td className="py-2 px-3 uppercase text-sky-400 font-bold">{ioc.type}</td>
                            <td className="py-2 px-3 text-slate-200">{ioc.defanged}</td>
                            <td className="py-2 px-3 text-slate-400 font-sans">{ioc.context_role}</td>
                            <td className="py-2 px-3 text-emerald-400">{ioc.threat_status}</td>
                          </tr>
                        ))}
                        {incidentDetail.iocs.length === 0 && (
                          <tr><td colSpan={4} className="py-3 text-center text-slate-500 font-sans">No IOCs extracted.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Extracted IOAs */}
                <div className="space-y-2 pt-2">
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold text-xs text-purple-400 uppercase tracking-wider flex items-center space-x-1.5">
                      <Crosshair className="w-3.5 h-3.5" />
                      <span>Extracted Indicators of Attack (IOA Behaviors & Detection)</span>
                    </h3>
                    <span className="text-[11px] text-slate-400 font-mono">
                      {incidentDetail.ioas?.length || 0} Behavioral Patterns
                    </span>
                  </div>
                  <div className="overflow-x-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#0c1220] text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="py-2 px-3">Type</th>
                          <th className="py-2 px-3">Pattern Name</th>
                          <th className="py-2 px-3">Technique ID</th>
                          <th className="py-2 px-3">Observed Behavior</th>
                          <th className="py-2 px-3">Recommended Detection Logic</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 bg-[#0f172a]">
                        {(incidentDetail.ioas || []).map((ioa, idx) => (
                          <tr key={idx}>
                            <td className="py-2 px-3 uppercase text-purple-400 font-bold">{ioa.type}</td>
                            <td className="py-2 px-3 text-white font-sans font-medium">{ioa.pattern_name}</td>
                            <td className="py-2 px-3 text-sky-400">{ioa.technique_id || 'TTP'}</td>
                            <td className="py-2 px-3 text-slate-300 font-sans max-w-xs">{ioa.observed_behavior}</td>
                            <td className="py-2 px-3 text-emerald-400 font-sans max-w-xs">{ioa.detection_logic}</td>
                          </tr>
                        ))}
                        {(!incidentDetail.ioas || incidentDetail.ioas.length === 0) && (
                          <tr><td colSpan={5} className="py-3 text-center text-slate-500 font-sans">No behavioral IOAs extracted yet.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Recommendations */}
                <div className="space-y-2 pt-2">
                  <h3 className="font-semibold text-xs text-slate-300 uppercase tracking-wider">Defensive Recommendations & Mitigations</h3>
                  <div className="space-y-2">
                    {incidentDetail.recommendations.map((r, idx) => (
                      <div key={idx} className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg flex items-start space-x-3 text-xs">
                        <span className="px-2 py-0.5 bg-sky-950 text-sky-400 border border-sky-800 rounded text-[10px] font-bold">
                          {r.category}
                        </span>
                        <div>
                          <strong className="text-white block">{r.title}</strong>
                          <span className="text-slate-400">{r.action_items}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: IOC EXPLORER */}
          {activeTab === 'iocs' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white">Indicators of Compromise (IOC) Explorer</h2>
                  <p className="text-xs text-slate-400">Searchable, normalized threat indicator database with safe defanging</p>
                </div>
                <div className="flex items-center space-x-2">
                  <button onClick={() => exportIOCs('json')} className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs rounded border border-slate-700 flex items-center space-x-1.5">
                    <Download className="w-3.5 h-3.5" />
                    <span>Export JSON</span>
                  </button>
                  <button onClick={() => exportIOCs('csv')} className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs rounded border border-slate-700 flex items-center space-x-1.5">
                    <Download className="w-3.5 h-3.5" />
                    <span>Export CSV</span>
                  </button>
                </div>
              </div>

              <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#0c1220] text-slate-400 border-b border-slate-800 uppercase tracking-wider">
                    <tr>
                      <th className="py-3 px-4">Type</th>
                      <th className="py-3 px-4">Defanged Value</th>
                      <th className="py-3 px-4">Raw Normalized</th>
                      <th className="py-3 px-4">Threat Status</th>
                      <th className="py-3 px-4">First Observed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {iocs.map(i => (
                      <tr key={i.id} className="hover:bg-slate-800/30">
                        <td className="py-3 px-4 text-sky-400 font-bold uppercase">{i.type}</td>
                        <td className="py-3 px-4 text-slate-200">{i.defanged}</td>
                        <td className="py-3 px-4 text-slate-500 truncate max-w-xs">{i.value}</td>
                        <td className="py-3 px-4 text-emerald-400">{i.threat_status}</td>
                        <td className="py-3 px-4 text-slate-400 font-sans">{i.first_seen ? new Date(i.first_seen).toLocaleDateString() : ''}</td>
                      </tr>
                    ))}
                    {iocs.length === 0 && (
                      <tr><td colSpan={5} className="py-8 text-center text-slate-500 font-sans">No IOCs recorded yet.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB: IOA EXPLORER (ATTACKS) */}
          {activeTab === 'ioas' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white">Indicators of Attack (IOA) Explorer</h2>
                  <p className="text-xs text-slate-400">Adversary behavioral patterns, execution mechanics, and recommended detection logic</p>
                </div>
                <div className="flex items-center space-x-2">
                  <button onClick={() => exportIOAs('json')} className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs rounded border border-slate-700 flex items-center space-x-1.5">
                    <Download className="w-3.5 h-3.5" />
                    <span>Export JSON</span>
                  </button>
                  <button onClick={() => exportIOAs('csv')} className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs rounded border border-slate-700 flex items-center space-x-1.5">
                    <Download className="w-3.5 h-3.5" />
                    <span>Export CSV</span>
                  </button>
                </div>
              </div>

              <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#0c1220] text-slate-400 border-b border-slate-800 uppercase tracking-wider">
                    <tr>
                      <th className="py-3 px-4">IOA Type</th>
                      <th className="py-3 px-4">Pattern Name</th>
                      <th className="py-3 px-4">Technique</th>
                      <th className="py-3 px-4">Observed Behavior</th>
                      <th className="py-3 px-4">Detection Logic</th>
                      <th className="py-3 px-4">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {ioas.map(ioa => (
                      <tr key={ioa.id} className="hover:bg-slate-800/30">
                        <td className="py-3 px-4 text-purple-400 font-bold uppercase">{ioa.type}</td>
                        <td className="py-3 px-4 text-white font-sans font-medium">{ioa.pattern_name}</td>
                        <td className="py-3 px-4 text-sky-400">{ioa.technique_id || 'TTP'}</td>
                        <td className="py-3 px-4 text-slate-300 font-sans max-w-sm">{ioa.observed_behavior}</td>
                        <td className="py-3 px-4 text-emerald-400 font-sans max-w-sm">{ioa.detection_logic}</td>
                        <td className="py-3 px-4 text-slate-400">{((ioa.confidence || 0.9) * 100).toFixed(0)}%</td>
                      </tr>
                    ))}
                    {ioas.length === 0 && (
                      <tr><td colSpan={6} className="py-8 text-center text-slate-500 font-sans">No Indicators of Attack recorded yet. Trigger an investigation to analyze behavioral IOAs.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: KNOWLEDGE BASE & RAG */}
          {activeTab === 'knowledge' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="bg-[#0f172a] border border-slate-800 p-6 rounded-xl space-y-4">
                <h3 className="text-sm font-semibold text-white">Semantic RAG Search (text-embedding-004)</h3>
                <div className="flex space-x-3">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search historical breaches, techniques, or ransomware families..."
                    className="flex-1 bg-[#0c1220] border border-slate-700 px-4 py-2 rounded-lg text-xs text-white focus:outline-none focus:border-sky-500"
                  />
                  <button
                    onClick={handleKnowledgeSearch}
                    disabled={isSearching}
                    className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold flex items-center space-x-1.5"
                  >
                    <Search className="w-3.5 h-3.5" />
                    <span>Search</span>
                  </button>
                </div>

                {searchResults.length > 0 && (
                  <div className="space-y-3 pt-4">
                    <h4 className="text-xs font-semibold text-slate-300">Top Semantic Matches</h4>
                    {searchResults.map((res, idx) => (
                      <div key={idx} className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg text-xs space-y-1">
                        <div className="flex items-center justify-between text-slate-400 text-[11px]">
                          <span className="font-mono text-sky-400">Score: {(res.similarity * 100).toFixed(1)}%</span>
                          <span>Doc: {res.metadata?.title || res.document_id}</span>
                        </div>
                        <p className="text-slate-200">{res.content}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Upload Document */}
              <div className="bg-[#0f172a] border border-slate-800 p-6 rounded-xl space-y-4">
                <h3 className="text-sm font-semibold text-white">Index New Security Document</h3>
                <div className="space-y-3 text-xs">
                  <input
                    type="text"
                    value={uploadTitle}
                    onChange={(e) => setUploadTitle(e.target.value)}
                    placeholder="Document Title (e.g., CISA Alert AA24-123A)"
                    className="w-full bg-[#0c1220] border border-slate-700 px-4 py-2 rounded-lg text-white"
                  />
                  <input
                    type="text"
                    value={uploadSourceUrl}
                    onChange={(e) => setUploadSourceUrl(e.target.value)}
                    placeholder="Source URL"
                    className="w-full bg-[#0c1220] border border-slate-700 px-4 py-2 rounded-lg text-white"
                  />
                  <textarea
                    rows={4}
                    value={uploadContent}
                    onChange={(e) => setUploadContent(e.target.value)}
                    placeholder="Paste advisory content or incident report text here..."
                    className="w-full bg-[#0c1220] border border-slate-700 p-3 rounded-lg text-white"
                  />
                  <button
                    onClick={handleUploadDocument}
                    disabled={loading}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-semibold text-xs"
                  >
                    Generate Embeddings & Index
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: NOTIFICATION CENTER */}
          {activeTab === 'notifications' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white">Gmail Notification Center</h2>
                  <p className="text-xs text-slate-400">Audit trail of HTML threat intelligence reports and dispatch logs</p>
                </div>
                <button
                  onClick={sendTestNotification}
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold"
                >
                  Dispatch Test Alert
                </button>
              </div>

              <div className="space-y-4">
                {notifications.map((notif) => (
                  <div key={notif.id} className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <div className="flex items-center space-x-3">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                          notif.delivery_status === 'SENT' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                          'bg-sky-950 text-sky-400 border border-sky-800'
                        }`}>
                          {notif.delivery_status}
                        </span>
                        <strong className="text-xs text-white">{notif.subject}</strong>
                      </div>
                      <span className="text-[11px] text-slate-400 font-mono">
                        {notif.created_at ? new Date(notif.created_at).toLocaleString() : ''}
                      </span>
                    </div>

                    <div className="text-xs text-slate-400">
                      Recipient: <span className="text-slate-200 font-mono">{notif.recipient}</span>
                    </div>

                    {/* Interactive HTML Email Preview Accordion */}
                    <details className="text-xs bg-[#0c1220] border border-slate-800 rounded-lg p-3">
                      <summary className="cursor-pointer text-sky-400 font-medium">View Formatted Email Body (HTML / Plain)</summary>
                      <div className="mt-3 space-y-2">
                        <pre className="p-3 bg-slate-900 border border-slate-800 rounded text-slate-300 font-mono whitespace-pre-wrap max-h-60 overflow-y-auto">
                          {notif.plain_preview}
                        </pre>
                      </div>
                    </details>
                  </div>
                ))}
                {notifications.length === 0 && (
                  <div className="text-center py-12 text-slate-500 text-xs">
                    No notifications recorded yet.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 8: SETTINGS & CONFIG */}
          {activeTab === 'settings' && (
            <div className="space-y-6 max-w-4xl mx-auto">
              <div className="bg-[#0f172a] border border-slate-800 p-6 rounded-xl space-y-4">
                <h3 className="text-sm font-semibold text-white">System Architecture & Integrations</h3>
                
                <div className="space-y-3 text-xs">
                  <div className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg flex justify-between items-center">
                    <div>
                      <strong className="text-white block">Gemini Model</strong>
                      <span className="text-slate-400">Vertex AI endpoint in global region</span>
                    </div>
                    <span className="font-mono text-sky-400">gemini-3.8-flash</span>
                  </div>

                  <div className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg flex justify-between items-center">
                    <div>
                      <strong className="text-white block">RAG Embedding Model</strong>
                      <span className="text-slate-400">Dense vector representations</span>
                    </div>
                    <span className="font-mono text-emerald-400">text-embedding-004</span>
                  </div>

                  <div className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg flex justify-between items-center">
                    <div>
                      <strong className="text-white block">GCP Project</strong>
                      <span className="text-slate-400">Current Qwiklabs Project</span>
                    </div>
                    <span className="font-mono text-slate-300">qwiklabs-gcp-03-fd05546dff54</span>
                  </div>

                  <div className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg flex justify-between items-center">
                    <div>
                      <strong className="text-white block">Feed Polling Schedule</strong>
                      <span className="text-slate-400">Background APScheduler poller</span>
                    </div>
                    <span className="font-mono text-slate-300">Every 15 minutes</span>
                  </div>
                </div>

                <div className="pt-4 border-t border-slate-800">
                  <h4 className="text-xs font-semibold text-slate-200 mb-2">Enabling Live Gmail Dispatch</h4>
                  <div className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg text-xs text-slate-400 leading-relaxed font-mono">
                    1. Create OAuth 2.0 Desktop credentials in Google Cloud Console.<br/>
                    2. Save credentials JSON as backend/credentials.json.<br/>
                    3. Run OAuth flow to generate token.json with scope 'https://www.googleapis.com/auth/gmail.send'.<br/>
                    4. In preview mode, all HTML emails are formatted and viewable in the Notification Center.
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* UNIFIED GLOBAL SEARCH MODAL */}
        {showSearchModal && (
          <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-start justify-center pt-16 px-4">
            <div className="bg-[#0f172a] border border-slate-700 rounded-2xl w-full max-w-4xl max-h-[80vh] flex flex-col shadow-2xl overflow-hidden">
              {/* Modal Header */}
              <div className="p-4 bg-[#0c1220] border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center space-x-3 flex-1">
                  <Search className="w-4 h-4 text-sky-400" />
                  <input
                    type="text"
                    value={globalQuery}
                    onChange={(e) => setGlobalQuery(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleGlobalSearch(); }}
                    placeholder="Search past threat reports, IOCs, IOAs, or semantic vectors..."
                    className="w-full bg-transparent text-sm text-white focus:outline-none placeholder:text-slate-500"
                    autoFocus
                  />
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleGlobalSearch()}
                    disabled={isGlobalSearching}
                    className="px-3 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold"
                  >
                    {isGlobalSearching ? 'Searching...' : 'Search'}
                  </button>
                  <button
                    onClick={() => setShowSearchModal(false)}
                    className="p-1 text-slate-400 hover:text-white rounded"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              {/* Modal Body: Results by Category */}
              <div className="p-6 overflow-y-auto space-y-6 text-xs">
                {isGlobalSearching && (
                  <div className="text-center py-12 text-slate-400 animate-pulse">
                    Scanning incident reports, IOC defanged records, IOA attack behaviors, and semantic vectors...
                  </div>
                )}

                {!isGlobalSearching && globalSearchResults && (
                  <>
                    <div className="text-[11px] font-mono text-slate-400">
                      Found {globalSearchResults.total_matches} results for "{globalSearchResults.query}"
                    </div>

                    {/* Threat Reports */}
                    {globalSearchResults.reports.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-semibold text-sky-400 uppercase tracking-wider flex items-center space-x-1.5">
                          <FileText className="w-3.5 h-3.5" />
                          <span>Threat Intelligence Reports ({globalSearchResults.reports.length})</span>
                        </h4>
                        <div className="space-y-2">
                          {globalSearchResults.reports.map((r: IncidentSummary) => (
                            <div
                              key={r.id}
                              onClick={() => {
                                setShowSearchModal(false);
                                loadIncidentDetail(r.id);
                              }}
                              className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg hover:border-sky-500/50 cursor-pointer transition flex items-center justify-between"
                            >
                              <div className="space-y-1 max-w-2xl">
                                <div className="flex items-center space-x-2">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                    r.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300' : 'bg-amber-950 text-amber-300'
                                  }`}>
                                    {r.severity}
                                  </span>
                                  <strong className="text-white">{r.title}</strong>
                                </div>
                                <p className="text-slate-400 line-clamp-1">{r.summary}</p>
                              </div>
                              <span className="text-[11px] text-sky-400 hover:underline">View Analysis →</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Indicators of Compromise (IOCs) */}
                    {globalSearchResults.iocs.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-semibold text-amber-400 uppercase tracking-wider flex items-center space-x-1.5">
                          <Binary className="w-3.5 h-3.5" />
                          <span>Matched Indicators of Compromise ({globalSearchResults.iocs.length})</span>
                        </h4>
                        <div className="grid grid-cols-2 gap-2 font-mono">
                          {globalSearchResults.iocs.map((ioc: IOCItem) => (
                            <div key={ioc.id} className="p-2.5 bg-[#0c1220] border border-slate-800 rounded-lg flex items-center justify-between">
                              <span className="text-amber-400 uppercase font-bold text-[10px]">{ioc.type}</span>
                              <span className="text-slate-200 truncate max-w-xs">{ioc.defanged || ioc.value}</span>
                              <span className="text-emerald-400 text-[10px]">{ioc.threat_status}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Indicators of Attack (IOAs) */}
                    {globalSearchResults.ioas.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-semibold text-purple-400 uppercase tracking-wider flex items-center space-x-1.5">
                          <Crosshair className="w-3.5 h-3.5" />
                          <span>Matched Indicators of Attack ({globalSearchResults.ioas.length})</span>
                        </h4>
                        <div className="space-y-2">
                          {globalSearchResults.ioas.map((ioa: IOAItem) => (
                            <div key={ioa.id} className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="font-semibold text-purple-300 font-sans">{ioa.pattern_name}</span>
                                <span className="px-2 py-0.5 bg-purple-950/80 border border-purple-800/80 text-purple-300 rounded text-[10px] font-mono">
                                  {ioa.type}
                                </span>
                              </div>
                              <p className="text-slate-300 font-sans">{ioa.observed_behavior}</p>
                              <div className="text-emerald-400 font-mono text-[11px]">
                                Detection: {ioa.detection_logic}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Semantic Vector Knowledge Matches */}
                    {globalSearchResults.historical_rag.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-semibold text-emerald-400 uppercase tracking-wider flex items-center space-x-1.5">
                          <Database className="w-3.5 h-3.5" />
                          <span>Historical RAG Semantic Matches ({globalSearchResults.historical_rag.length})</span>
                        </h4>
                        <div className="space-y-2">
                          {globalSearchResults.historical_rag.map((k, idx: number) => (
                            <div key={idx} className="p-3 bg-[#0c1220] border border-slate-800 rounded-lg space-y-1">
                              <div className="flex items-center justify-between text-[11px] text-slate-400">
                                <span className="text-emerald-400 font-mono">Relevance: {(k.score * 100).toFixed(1)}%</span>
                                <span>{k.title || 'Historical Document'}</span>
                              </div>
                              <p className="text-slate-300 font-sans line-clamp-2">{k.text}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {globalSearchResults.total_matches === 0 && (
                      <div className="text-center py-12 text-slate-500">
                        No matches found across reports, IOCs, IOAs, or semantic vectors for "{globalSearchResults.query}".
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
