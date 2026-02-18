import React from 'react'
import './Home.css'
import Navbar from '../../Components/Navbar/Navbar'
import Hero from '../../Components/Hero/Hero'
import Features from '../../Components/Features/Features'
import Pricing from '../Pricing/Pricing'
import Testimonial from '../../Components/Testimonial/Testimonial'
import CTA from '../../Components/CTA/CTA'
import About from '../../Components/About/About'
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

      <section id="testimonial">
        <Testimonial/>
      </section>

      <section id="cta">
        <CTA/>
      </section>

      <section id="about">
        <About/>
      </section>

      <section id="footer">
        <Footer/>
      </section>
    </div>
  )
}

export default Home
