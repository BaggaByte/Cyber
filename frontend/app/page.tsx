"use client";

import { useState, useEffect } from 'react';
import Cookies from 'js-cookie';
import { Shield, Activity, Lock, User, Building, ArrowRight, Server, CheckCircle, Target, ChevronDown } from 'lucide-react';
import ThemeSwitcher from './components/ThemeSwitcher';

export default function Home() {
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [jobTitle, setJobTitle] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  
  const calculateStrength = (pwd: string) => {
    let strength = 0;
    if (pwd.length >= 8) strength += 25;
    if (/[A-Z]/.test(pwd)) strength += 25;
    if (/[0-9]/.test(pwd)) strength += 25;
    if (/[^A-Za-z0-9]/.test(pwd)) strength += 25;
    return strength;
  };
  const passwordStrength = calculateStrength(password);
  
  const [telemetry, setTelemetry] = useState({ sentinel: 0, aegis: 0, nexus: 0 });

  useEffect(() => {
    const savedToken = Cookies.get('token');
    if (savedToken) {
      setToken(savedToken);
    }
    
    const interval = setInterval(() => {
      setTelemetry(prev => ({
        sentinel: Math.min(prev.sentinel + 400, 14392),
        aegis: Math.min(prev.aegis + 25, 845),
        nexus: Math.min(prev.nexus + 3, 98)
      }));
    }, 50);
    return () => clearInterval(interval);
  }, []);

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAuthenticating(true);
    setLoginError("");

    const endpoint = isRegistering ? "/api/register" : "/api/login";
    const payload = isRegistering ? { 
      email, password, org_name: orgName, first_name: firstName, last_name: lastName, job_title: jobTitle 
    } : { email, password };

    try {
      const res = await fetch(`${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        const data = await res.json();
        if (data.access_token) {
          Cookies.set('token', data.access_token, { path: '/' });
          setToken(data.access_token);
        } else {
          alert("Registration successful! Please login.");
          setIsRegistering(false);
        }
      } else {
       if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || "Connection error. Ensure API is running and restart npm run dev.");
      }
      }
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : "Connection error. Ensure API is running.");
    } finally {
      setIsAuthenticating(false);
    }
  };

  const scrollToHub = () => {
    document.getElementById('hub-content')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="flex flex-col min-h-screen relative w-full font-sans">
      
      {/* Floating Theme Switcher */}
      <div className="absolute top-6 right-6 z-50">
        <ThemeSwitcher />
      </div>
      
      {/* HERO SECTION: Split-Screen Auth */}
      <div className="flex min-h-screen w-full">
        
        {/* Left Side: Animated Brand Area */}
        <div className="flex-1 relative bg-slate-100 dark:bg-slate-950 overflow-hidden flex flex-col justify-center p-12 lg:p-24 border-r border-slate-200 dark:border-slate-800">
          <div className="scanner-beam absolute left-0 w-full h-1 bg-brand-primary shadow-[0_0_20px_5px_rgba(240,78,35,0.5)] z-10"></div>
          
          <div className="animate-float absolute top-[20%] right-[20%] opacity-5 dark:opacity-10 pointer-events-none">
            <Shield size={240} className="text-brand-primary" />
          </div>
          <div className="animate-spin-slow absolute bottom-[15%] left-[15%] opacity-5 dark:opacity-10 pointer-events-none">
            <Activity size={300} className="text-emerald-500" />
          </div>

          <div className="relative z-10 max-w-lg">
            <div className="flex items-center gap-4 mb-8">
              <div className="w-14 h-14 bg-brand-primary rounded-xl flex items-center justify-center shadow-lg shadow-brand-primary/30 relative">
                <Shield size={28} className="text-white" />
                <div className="absolute inset-0 rounded-xl border border-white/20 animate-pulse-glow pointer-events-none"></div>
              </div>
              <h1 className="text-5xl lg:text-6xl font-extrabold tracking-tight text-slate-900 dark:text-white">
                Sentinel<span className="text-brand-primary">AI</span>
              </h1>
            </div>
            <p className="text-lg lg:text-xl text-slate-600 dark:text-slate-400 font-light leading-relaxed">
              The autonomous security operations center. Continuously map your attack surface, execute AI-driven reconnaissance, and remediate vulnerabilities before they are exploited.
            </p>
          </div>
        </div>

        {/* Right Side: Auth Form */}
        <div className="w-full max-w-[500px] flex items-center justify-center p-10 bg-white dark:bg-slate-900 shadow-2xl z-20">
          {!token ? (
            <div className="w-full max-w-[380px]">
              <h2 className="text-3xl font-bold mb-2 text-slate-900 dark:text-white tracking-tight">
                {isRegistering ? "Create workspace" : "Welcome back"}
              </h2>
              <p className="text-sm text-slate-500 dark:text-slate-400 mb-8">
                {isRegistering ? "Deploy your autonomous SOC in seconds." : "Enter your credentials to access the Saga Ecosystem."}
              </p>

              <form onSubmit={handleAuth} className="flex flex-col gap-5">
                <div className="relative group">
                  <User size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within:text-brand-primary transition-colors" />
                  <input 
                    type="email" 
                    placeholder="Email Address" 
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl py-3 pl-11 pr-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-primary/50 focus:border-brand-primary transition-all shadow-sm"
                    onChange={e => setEmail(e.target.value)} 
                    required 
                  />
                </div>

                <div className="relative group">
                  <Lock size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within:text-brand-primary transition-colors" />
                  <input 
                    type="password" 
                    placeholder="Password" 
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl py-3 pl-11 pr-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-primary/50 focus:border-brand-primary transition-all shadow-sm"
                    onChange={e => setPassword(e.target.value)} 
                    required 
                  />
                </div>
                
                {isRegistering && (
                  <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden mt-[-10px] mb-1">
                    <div 
                      className={`h-full transition-all duration-300 ${
                        passwordStrength < 50 ? 'bg-red-500' : 
                        passwordStrength < 100 ? 'bg-amber-500' : 'bg-emerald-500'
                      }`} 
                      style={{ width: `${passwordStrength}%` }}
                    ></div>
                    {passwordStrength < 100 && (
                      <p className="text-[10px] text-slate-500 mt-2">Requires 8+ chars, uppercase, number, & symbol.</p>
                    )}
                  </div>
                )}

                {isRegistering && (
                  <div className="grid grid-cols-2 gap-4 animate-slide-up">
                    <div className="relative group">
                      <input 
                        type="text" 
                        placeholder="First Name" 
                        className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl py-3 px-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-primary/50 transition-all shadow-sm"
                        onChange={e => setFirstName(e.target.value)} 
                        required={isRegistering} 
                      />
                    </div>
                    <div className="relative group">
                      <input 
                        type="text" 
                        placeholder="Last Name" 
                        className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl py-3 px-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-primary/50 transition-all shadow-sm"
                        onChange={e => setLastName(e.target.value)} 
                        required={isRegistering} 
                      />
                    </div>
                  </div>
                )}

                {isRegistering && (
                  <div className="relative group animate-slide-up delay-100">
                    <input 
                      type="text" 
                      placeholder="Job Title (e.g. CISO, Security Engineer)" 
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl py-3 px-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-primary/50 transition-all shadow-sm"
                      onChange={e => setJobTitle(e.target.value)} 
                      required={isRegistering} 
                    />
                  </div>
                )}

                {isRegistering && (
                  <div className="relative group animate-slide-up delay-200">
                    <Building size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within:text-brand-primary transition-colors" />
                    <input 
                      type="text" 
                      placeholder="Organization Name" 
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl py-3 pl-11 pr-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-primary/50 focus:border-brand-primary transition-all shadow-sm"
                      onChange={e => setOrgName(e.target.value)} 
                      required 
                    />
                  </div>
                )}

                <button 
                  type="submit" 
                  disabled={isAuthenticating || (isRegistering && passwordStrength < 100)}
                  className="mt-2 w-full py-3.5 bg-brand-primary hover:bg-brand-secondary text-white rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all hover:-translate-y-0.5 hover:shadow-lg hover:shadow-brand-primary/40 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isAuthenticating ? "Authenticating..." : (isRegistering ? "Register Workspace" : "Access Ecosystem")}
                  <ArrowRight size={16} />
                </button>
                {loginError && <div className="text-red-500 text-sm text-center font-medium bg-red-50 dark:bg-red-950/50 py-2 rounded-lg">{loginError}</div>}
              </form>

              <div className="mt-8 text-center text-sm text-slate-500 dark:text-slate-400">
                {isRegistering ? "Already have an account?" : "Don't have an account?"}
                <button 
                  onClick={(e) => { e.preventDefault(); setIsRegistering(!isRegistering); }}
                  className="ml-2 font-semibold text-brand-primary hover:text-brand-secondary transition-colors"
                >
                  {isRegistering ? "Log in" : "Register"}
                </button>
              </div>
            </div>
          ) : (
            <div className="w-full max-w-[380px] text-center animate-fade-in">
              <div className="w-20 h-20 bg-emerald-100 dark:bg-emerald-900/30 rounded-full flex items-center justify-center mx-auto mb-6 shadow-inner border border-emerald-200 dark:border-emerald-800">
                <CheckCircle size={40} className="text-emerald-600 dark:text-emerald-400" />
              </div>
              <h2 className="text-3xl font-bold mb-3 text-slate-900 dark:text-white tracking-tight">
                Authentication Successful
              </h2>
              <p className="text-slate-500 dark:text-slate-400 text-base mb-8 leading-relaxed">
                You are securely connected to the Saga Enterprise Ecosystem.
              </p>
              <button 
                onClick={scrollToHub} 
                className="inline-flex items-center gap-2 bg-brand-primary hover:bg-brand-secondary text-white px-8 py-3.5 rounded-xl font-semibold transition-all hover:-translate-y-0.5 hover:shadow-lg hover:shadow-brand-primary/40"
              >
                Enter Hub
                <ChevronDown size={18} />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* SAGA ENTERPRISE HUB SECTIONS */}
      <main id="hub-content" className="flex flex-col items-center w-full px-6 py-32 bg-slate-50 dark:bg-slate-950">
        
        <div className="text-center max-w-3xl mb-24">
          <div className="inline-flex items-center gap-2 bg-brand-primary/10 border border-brand-primary/20 px-4 py-1.5 rounded-full text-brand-primary font-bold text-xs tracking-wider mb-6 uppercase">
            Saga Enterprise Hub
          </div>
          <h1 className="text-5xl md:text-6xl font-extrabold text-slate-900 dark:text-white tracking-tight mb-6 leading-tight">
            Unified Security <span className="text-brand-primary">Ecosystem</span>
          </h1>
          <p className="text-lg md:text-xl text-slate-600 dark:text-slate-400 leading-relaxed font-light">
            The autonomous security operations center. Continuously map your attack surface, execute AI-driven reconnaissance, and remediate vulnerabilities before they are exploited across all enterprise layers.
          </p>
        </div>

        {/* Telemetry Dashboard */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-5xl mb-24 animate-slide-up delay-100">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 text-center shadow-sm hover:shadow-md transition-shadow">
            <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 mb-4 uppercase tracking-wider">Active Threats Mitigated</h3>
            <div className="text-5xl font-extrabold text-brand-primary font-mono tracking-tight mb-2">{telemetry.sentinel.toLocaleString()}</div>
            <p className="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">Sentinel AI</p>
          </div>
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 text-center shadow-sm hover:shadow-md transition-shadow">
            <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 mb-4 uppercase tracking-wider">Vulnerabilities Patched</h3>
            <div className="text-5xl font-extrabold text-emerald-500 font-mono tracking-tight mb-2">{telemetry.aegis.toLocaleString()}</div>
            <p className="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">Aegis AI</p>
          </div>
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 text-center shadow-sm hover:shadow-md transition-shadow">
            <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 mb-4 uppercase tracking-wider">Global Compliance</h3>
            <div className="text-5xl font-extrabold text-blue-500 font-mono tracking-tight mb-2">{telemetry.nexus.toLocaleString()}%</div>
            <p className="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">Nexus AI</p>
          </div>
        </div>

        {/* Platforms Grid (Glassmorphism Cards) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 w-full max-w-6xl mb-32">
          
          <a href={token ? "/dashboard" : "#"} onClick={(e) => { if(!token) { e.preventDefault(); alert("Please authenticate first."); } }} className="group relative bg-white/50 dark:bg-slate-900/50 backdrop-blur-xl border border-slate-200 dark:border-slate-800 rounded-3xl p-10 flex flex-col items-center text-center hover:-translate-y-2 hover:shadow-[0_20px_40px_-15px_rgba(0,0,0,0.1)] transition-all duration-300 overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-brand-primary opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
            <div className="w-20 h-20 rounded-2xl bg-brand-primary/10 dark:bg-brand-primary/20 flex items-center justify-center mb-8 shadow-inner shadow-brand-primary/20 group-hover:scale-110 transition-transform duration-500">
              <Shield size={36} className="text-brand-primary" />
            </div>
            <h2 className="text-2xl font-bold mb-4 text-slate-900 dark:text-white">Sentinel AI</h2>
            <p className="text-slate-600 dark:text-slate-400 mb-8 leading-relaxed">The autonomous SOC. Continuously map your attack surface, execute AI reconnaissance, and proactively remediate vulnerabilities.</p>
            <div className="mt-auto bg-slate-900 dark:bg-white text-white dark:text-slate-900 group-hover:bg-brand-primary dark:group-hover:bg-brand-primary dark:group-hover:text-white px-8 py-3 rounded-xl font-semibold w-full transition-colors duration-300">Launch Sentinel</div>
          </a>

          <a href={token ? "/aegis/" : "#"} onClick={(e) => { if(!token) { e.preventDefault(); alert("Please authenticate first."); } }} className="group relative bg-white/50 dark:bg-slate-900/50 backdrop-blur-xl border border-slate-200 dark:border-slate-800 rounded-3xl p-10 flex flex-col items-center text-center hover:-translate-y-2 hover:shadow-[0_20px_40px_-15px_rgba(0,0,0,0.1)] transition-all duration-300 overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
            <div className="w-20 h-20 rounded-2xl bg-emerald-500/10 dark:bg-emerald-500/20 flex items-center justify-center mb-8 shadow-inner shadow-emerald-500/20 group-hover:scale-110 transition-transform duration-500">
              <Server size={36} className="text-emerald-500" />
            </div>
            <h2 className="text-2xl font-bold mb-4 text-slate-900 dark:text-white">Aegis AI</h2>
            <p className="text-slate-600 dark:text-slate-400 mb-8 leading-relaxed">Advanced Static Code Review and AI Vulnerability Remediation Dashboard. Secure your codebase at the speed of development.</p>
            <div className="mt-auto bg-slate-900 dark:bg-white text-white dark:text-slate-900 group-hover:bg-emerald-500 dark:group-hover:bg-emerald-500 dark:group-hover:text-white px-8 py-3 rounded-xl font-semibold w-full transition-colors duration-300">Launch Aegis</div>
          </a>

          <a href={token ? "/nexus/" : "#"} onClick={(e) => { if(!token) { e.preventDefault(); alert("Please authenticate first."); } }} className="group relative bg-white/50 dark:bg-slate-900/50 backdrop-blur-xl border border-slate-200 dark:border-slate-800 rounded-3xl p-10 flex flex-col items-center text-center hover:-translate-y-2 hover:shadow-[0_20px_40px_-15px_rgba(0,0,0,0.1)] transition-all duration-300 overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-blue-500 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
            <div className="w-20 h-20 rounded-2xl bg-blue-500/10 dark:bg-blue-500/20 flex items-center justify-center mb-8 shadow-inner shadow-blue-500/20 group-hover:scale-110 transition-transform duration-500">
              <Target size={36} className="text-blue-500" />
            </div>
            <h2 className="text-2xl font-bold mb-4 text-slate-900 dark:text-white">Nexus AI</h2>
            <p className="text-slate-600 dark:text-slate-400 mb-8 leading-relaxed">Comprehensive Enterprise GRC Intelligence and reporting. Ensure compliance and monitor global risks autonomously.</p>
            <div className="mt-auto bg-slate-900 dark:bg-white text-white dark:text-slate-900 group-hover:bg-blue-500 dark:group-hover:bg-blue-500 dark:group-hover:text-white px-8 py-3 rounded-xl font-semibold w-full transition-colors duration-300">Launch Nexus</div>
          </a>

        </div>
        
        {/* About Section */}
        <div className="w-full max-w-6xl bg-white/50 dark:bg-slate-900/50 backdrop-blur-xl border border-slate-200 dark:border-slate-800 rounded-3xl p-12 lg:p-20 grid grid-cols-1 lg:grid-cols-2 gap-16 mb-24 shadow-sm">
          <div>
            <h2 className="text-3xl font-extrabold text-slate-900 dark:text-white flex items-center gap-4 mb-8">
              <div className="w-2 h-8 bg-brand-primary rounded-full"></div>
              Our Mission
            </h2>
            <p className="text-lg text-slate-600 dark:text-slate-400 leading-relaxed mb-6 font-light">
              At Saga Enterprise, our mission is to deliver next-generation AI security solutions that empower organizations to stay ahead of sophisticated cyber threats. We believe in autonomous, proactive defense systems that seamlessly integrate into your existing infrastructure.
            </p>
            <p className="text-lg text-slate-600 dark:text-slate-400 leading-relaxed font-light">
              By bringing together Sentinel AI for active reconnaissance, Aegis AI for code-level static analysis, and Nexus AI for overarching GRC governance, we provide a holistic, impenetrable security fabric for the modern enterprise.
            </p>
          </div>
          <div>
            <h2 className="text-3xl font-extrabold text-slate-900 dark:text-white mb-8">Leadership</h2>
            <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 p-8 rounded-2xl flex items-center gap-8 shadow-inner">
              <div className="w-24 h-24 rounded-full bg-gradient-to-br from-brand-primary to-brand-secondary flex items-center justify-center text-3xl font-black text-white shrink-0 shadow-lg shadow-brand-primary/30">
                GB
              </div>
              <div>
                <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-1">Gurnoor Bagga</h3>
                <p className="text-brand-primary font-semibold mb-3">Chief Executive Officer</p>
                <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">Visionary leader behind the Saga Unified Security platform, driving innovation in AI-native cybersecurity and autonomous enterprise defense.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Pricing Section */}
        <div className="w-full max-w-6xl flex flex-col items-center">
          <h2 className="text-4xl font-extrabold text-slate-900 dark:text-white mb-4">Enterprise Subscriptions</h2>
          <p className="text-lg text-slate-600 dark:text-slate-400 mb-16 text-center">Choose the right level of autonomous security for your organization. Flexible plans built for scale.</p>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 w-full">
            <div className="bg-white/50 dark:bg-slate-900/50 backdrop-blur-xl border border-slate-200 dark:border-slate-800 rounded-3xl p-10 text-center hover:-translate-y-1 transition-transform">
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">Professional</h3>
              <div className="text-5xl font-extrabold text-slate-900 dark:text-white tracking-tight mb-8">$499<span className="text-lg text-slate-500 dark:text-slate-500 font-medium">/mo</span></div>
              <ul className="space-y-4 text-left">
                <li className="flex items-center gap-3 text-slate-600 dark:text-slate-300 pb-4 border-b border-slate-200 dark:border-slate-800"><CheckCircle size={18} className="text-emerald-500 shrink-0" /> Access to Sentinel AI</li>
                <li className="flex items-center gap-3 text-slate-600 dark:text-slate-300 pb-4 border-b border-slate-200 dark:border-slate-800"><CheckCircle size={18} className="text-emerald-500 shrink-0" /> Standard Code Scanning</li>
                <li className="flex items-center gap-3 text-slate-600 dark:text-slate-300 pb-4 border-b border-slate-200 dark:border-slate-800"><CheckCircle size={18} className="text-emerald-500 shrink-0" /> Basic GRC Reporting</li>
                <li className="flex items-center gap-3 text-slate-600 dark:text-slate-300"><CheckCircle size={18} className="text-emerald-500 shrink-0" /> Email Support</li>
              </ul>
            </div>
            
            <div className="relative bg-white dark:bg-slate-900 border-2 border-brand-primary rounded-3xl p-10 text-center scale-105 shadow-2xl z-10">
              <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-brand-primary text-white text-xs font-bold px-4 py-1.5 rounded-full uppercase tracking-wider">Most Popular</div>
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">Enterprise</h3>
              <div className="text-5xl font-extrabold text-slate-900 dark:text-white tracking-tight mb-8">$1,499<span className="text-lg text-slate-500 dark:text-slate-500 font-medium">/mo</span></div>
              <ul className="space-y-4 text-left">
                <li className="flex items-center gap-3 text-slate-700 dark:text-slate-200 pb-4 border-b border-slate-100 dark:border-slate-800"><CheckCircle size={18} className="text-brand-primary shrink-0" /> Full Unified Access</li>
                <li className="flex items-center gap-3 text-slate-700 dark:text-slate-200 pb-4 border-b border-slate-100 dark:border-slate-800"><CheckCircle size={18} className="text-brand-primary shrink-0" /> Unlimited Repositories</li>
                <li className="flex items-center gap-3 text-slate-700 dark:text-slate-200 pb-4 border-b border-slate-100 dark:border-slate-800"><CheckCircle size={18} className="text-brand-primary shrink-0" /> Real-time autonomous SOC</li>
                <li className="flex items-center gap-3 text-slate-700 dark:text-slate-200 pb-4 border-b border-slate-100 dark:border-slate-800"><CheckCircle size={18} className="text-brand-primary shrink-0" /> Advanced Compliance</li>
                <li className="flex items-center gap-3 text-slate-700 dark:text-slate-200"><CheckCircle size={18} className="text-brand-primary shrink-0" /> 24/7 Priority Support</li>
              </ul>
            </div>

            <div className="bg-white/50 dark:bg-slate-900/50 backdrop-blur-xl border border-slate-200 dark:border-slate-800 rounded-3xl p-10 text-center hover:-translate-y-1 transition-transform">
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">Custom</h3>
              <div className="text-5xl font-extrabold text-slate-900 dark:text-white tracking-tight mb-8">Contact<span className="text-lg text-slate-500 dark:text-slate-500 font-medium"> Us</span></div>
              <ul className="space-y-4 text-left">
                <li className="flex items-center gap-3 text-slate-600 dark:text-slate-300 pb-4 border-b border-slate-200 dark:border-slate-800"><CheckCircle size={18} className="text-slate-900 dark:text-white shrink-0" /> Dedicated Success Manager</li>
                <li className="flex items-center gap-3 text-slate-600 dark:text-slate-300 pb-4 border-b border-slate-200 dark:border-slate-800"><CheckCircle size={18} className="text-slate-900 dark:text-white shrink-0" /> Custom Integration APIs</li>
                <li className="flex items-center gap-3 text-slate-600 dark:text-slate-300 pb-4 border-b border-slate-200 dark:border-slate-800"><CheckCircle size={18} className="text-slate-900 dark:text-white shrink-0" /> On-premise Deployment</li>
                <li className="flex items-center gap-3 text-slate-600 dark:text-slate-300"><CheckCircle size={18} className="text-slate-900 dark:text-white shrink-0" /> Custom Threat Models</li>
              </ul>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
