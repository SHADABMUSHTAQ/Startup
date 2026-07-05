import React, { useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  Bell,
  BriefcaseBusiness,
  Camera,
  CheckCircle2,
  Globe2,
  Mail,
  MapPin,
  Phone,
  ShieldCheck,
  User,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../../../store/authStore";
import apiClient from "../../../api/apiClient";
import "./Profile.css";

const defaultProfile = {
  full_name: "",
  email: "",
  phone: "",
  company: "WarSOC Technologies",
  role: "Administrator",
  location: "Karachi, Pakistan",
  website: "https://warsoc.io",
  bio: "Security operations lead managing compliance, telemetry, and incident response workflows.",
  avatar: "",
  two_factor_enabled: false,
  billing_alerts: true,
  product_updates: false,
};

export default function Profile() {
  const navigate = useNavigate();
  const { user, role, plan_type, checkAuth } = useAuthStore();
  const [profile, setProfile] = useState(defaultProfile);
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const { data } = await apiClient.get('/auth/profile');
        const apiProfile = data.profile || {};
        const security = data.security || {};
        setProfile({
          ...defaultProfile,
          ...apiProfile,
          role: data.role || apiProfile.role || role || "Administrator",
          two_factor_enabled: Boolean(security.two_factor_enabled),
          billing_alerts: security.billing_alerts ?? apiProfile.billing_alerts ?? defaultProfile.billing_alerts,
          product_updates: security.product_updates ?? apiProfile.product_updates ?? defaultProfile.product_updates,
          full_name: apiProfile.full_name || user?.full_name || user?.name || user?.username || "User",
          email: apiProfile.email || user?.email || "",
        });
      } catch (err) {
        console.error("Failed to fetch profile", err);
        // Fallback to auth store info if API fails
        setProfile({
          ...defaultProfile,
          full_name: user?.full_name || user?.name || user?.username || "User",
          email: user?.email || "",
          role: role || "Administrator",
        });
      } finally {
        setLoading(false);
      }
    };
    fetchProfile();
  }, [role, user]);

  const initials = useMemo(() => {
    return (profile.full_name || "U")
      .split(" ")
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0])
      .join("")
      .toUpperCase() || "U";
  }, [profile.full_name]);

  const updateField = (field, value) => {
    setProfile((current) => ({ ...current, [field]: value }));
    setSaved(false);
  };

  const handleAvatar = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => updateField("avatar", reader.result);
    reader.readAsDataURL(file);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      await apiClient.put('/auth/profile', {
        full_name: profile.full_name,
        email: profile.email,
        phone: profile.phone,
        company: profile.company,
        location: profile.location,
        website: profile.website,
        bio: profile.bio,
        billing_alerts: profile.billing_alerts,
        product_updates: profile.product_updates,
        avatar: profile.avatar
      });
      await checkAuth();
      setSaved(true);
      window.setTimeout(() => navigate("/dashboard"), 900);
    } catch (err) {
      console.error("Failed to save profile", err);
      alert("Failed to save profile. Please try again.");
    }
  };

  if (loading) return null;

  return (
    <main className="profile-page">
      <section className="profile-hero">
        <div>
          <button className="profile-back-btn" type="button" onClick={() => navigate("/dashboard")}>
            <ArrowLeft size={16} />
            Back to Dashboard
          </button>
          <p className="profile-kicker">Account settings</p>
          <h1>My Profile</h1>
          <p>
            Manage your identity, contact details, company profile, and security preferences for the
            WarSOC portal.
          </p>
        </div>
        <div className="profile-status-card">
          <ShieldCheck size={22} />
          <div>
            <span>Workspace Status</span>
            <strong>Verified {plan_type || "Premium"} Account</strong>
          </div>
        </div>
      </section>

      <form className="profile-grid" onSubmit={handleSubmit}>
        <aside className="profile-card profile-overview">
          <label className="avatar-uploader">
            {profile.avatar ? (
              <img src={profile.avatar} alt={`${profile.full_name} avatar`} />
            ) : (
              <span>{initials}</span>
            )}
            <input type="file" accept="image/*" onChange={handleAvatar} />
            <div className="avatar-action">
              <Camera size={16} />
            </div>
          </label>

          <h2>{profile.full_name}</h2>
          <p>{profile.role}</p>

          <div className="profile-meta-list">
            <span>
              <Mail size={15} />
              {profile.email || "No email added"}
            </span>
            <span>
              <BriefcaseBusiness size={15} />
              {profile.company}
            </span>
            <span>
              <MapPin size={15} />
              {profile.location}
            </span>
          </div>
        </aside>

        <section className="profile-card profile-form-card">
          <div className="section-heading">
            <div>
              <p className="profile-kicker">Personal details</p>
              <h2>Profile Information</h2>
            </div>
            {saved && (
              <span className="saved-badge">
                <CheckCircle2 size={15} />
                Saved
              </span>
            )}
          </div>

          <div className="form-grid">
            <label>
              <span><User size={15} /> Full name</span>
              <input
                value={profile.full_name}
                onChange={(event) => updateField("full_name", event.target.value)}
                placeholder="Your full name"
              />
            </label>
            <label>
              <span><Mail size={15} /> Email address</span>
              <input
                type="email"
                value={profile.email}
                onChange={(event) => updateField("email", event.target.value)}
                placeholder="you@company.com"
              />
            </label>
            <label>
              <span><Phone size={15} /> Phone number</span>
              <input
                value={profile.phone}
                onChange={(event) => updateField("phone", event.target.value)}
                placeholder="+92 300 0000000"
              />
            </label>
            <label>
              <span><BriefcaseBusiness size={15} /> Company</span>
              <input
                value={profile.company}
                onChange={(event) => updateField("company", event.target.value)}
                placeholder="Company name"
              />
            </label>
            <label>
              <span><ShieldCheck size={15} /> Access role</span>
              <input
                value={profile.role}
                readOnly
                disabled
                style={{ opacity: 0.7, cursor: 'not-allowed', backgroundColor: 'var(--bg-dark)' }}
                placeholder="Admin, Analyst, Auditor"
              />
            </label>
            <label>
              <span><MapPin size={15} /> Location</span>
              <input
                value={profile.location}
                onChange={(event) => updateField("location", event.target.value)}
                placeholder="City, Country"
              />
            </label>
            <label className="full-span">
              <span><Globe2 size={15} /> Website</span>
              <input
                value={profile.website}
                onChange={(event) => updateField("website", event.target.value)}
                placeholder="https://example.com"
              />
            </label>
            <label className="full-span">
              <span>Professional bio</span>
              <textarea
                value={profile.bio}
                onChange={(event) => updateField("bio", event.target.value)}
                placeholder="Short professional profile"
                rows={4}
              />
            </label>
          </div>
        </section>

        <section className="profile-card preferences-card">
          <div className="section-heading">
            <div>
              <p className="profile-kicker">Preferences</p>
              <h2>Security and Notifications</h2>
            </div>
            <Bell size={22} />
          </div>

          <label className="toggle-row">
            <span>
              <strong>Two-factor protection</strong>
              <small>Configured through the dedicated two-factor setup flow.</small>
            </span>
            <input
              type="checkbox"
              checked={profile.two_factor_enabled}
              disabled
            />
          </label>
          <label className="toggle-row">
            <span>
              <strong>Billing and verification alerts</strong>
              <small>Receive payment, invoice, and activation status updates.</small>
            </span>
            <input
              type="checkbox"
              checked={profile.billing_alerts}
              onChange={(event) => updateField("billing_alerts", event.target.checked)}
            />
          </label>
          <label className="toggle-row">
            <span>
              <strong>Product updates</strong>
              <small>Get platform release and compliance feature announcements.</small>
            </span>
            <input
              type="checkbox"
              checked={profile.product_updates}
              onChange={(event) => updateField("product_updates", event.target.checked)}
            />
          </label>

          <button className="save-profile-btn" type="submit">
            Save Profile
          </button>
        </section>
      </form>
    </main>
  );
}
