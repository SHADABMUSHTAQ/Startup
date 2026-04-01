import React from 'react'
import './Home.css'
import Navbar from '../../Components/Navbar/Navbar'
import Hero from '../../Components/Hero/Hero'
import Features from '../../Components/Features/Features'
import Pricing from '../Pricing/Pricing'
import Contact from "../../Components/Contact/Contact"; 
import CTA from '../../Components/CTA/CTA'
import About from '../../Components/About/About'
// 🚀 1. Partners Component Import Kar Liya
import Partners from '../../Components/Partners/Partners' 
import Footer from '../../Components/Footer/Footer'

const Home = () => {
  return (
    <div>
      <Navbar />
      
      <section id="home">
        <Hero />
      </section>

      <section id="features">
        <Features />
      </section>

      <section id="pricing">
        <Pricing />
      </section>

      <section id="Contact">
        <Contact/>
      </section>

      <section id="cta">
        <CTA/>
      </section>

      <section id="about">
        <About/>
      </section>

      {/* 🚀 2. Partners Section - Bilkul Footer se upar */}
      <section id="partners">
        <Partners />
      </section>

      <section id="footer">
        <Footer/>
      </section>
    </div>
  )
}

export default Home