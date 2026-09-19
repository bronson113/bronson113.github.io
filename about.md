---
title: About Me
layout: about-me-page
---

{% capture about_shader %}
//https://iquilezles.org/articles/distfunctions2d/
float sdStar( in vec2 p, in float r, in int n, in float m)
{
    // next 4 lines can be precomputed for a given shape
    float an = 3.141593/float(n);
    float en = 3.141593/m;  // m is between 2 and n
    vec2  acs = vec2(cos(an),sin(an));
    vec2  ecs = vec2(cos(en),sin(en)); // ecs=vec2(0,1) for regular polygon

    float bn = mod(atan(p.x,p.y),2.0*an) - an;
    p = length(p)*vec2(cos(bn),abs(sin(bn)));
    p -= r*acs;
    p += ecs*clamp( -dot(p,ecs), 0.0, r*acs.y/ecs.y);
    return length(p)*sign(p.x);
}

//http://dev.thi.ng/gradients/
//[[1.028 0.078 0.858] [3.138 1.388 -0.442] [-0.993 1.853 1.288] [-0.885 2.115 5.774]]
//https://iquilezles.org/articles/palettes/
// cosine based palette, 4 vec3 params
vec3 palette( float t ) {
    vec3 a = vec3(1.028, 0.078, 0.858);
    vec3 b = vec3(3.138, 1.388, -0.442);
    vec3 c = vec3(-0.993, 1.853, 1.288);
    vec3 d = vec3(-0.885, 2.115, 5.774);

    return a + b*cos( 6.28318*(c*t+d) );
}


void mainImage( out vec4 fragColor, in vec2 fragCoord )
{
    // Normalized pixel coord without streching
    vec2 uv = (fragCoord * 2.0 - iResolution.xy) / iResolution.y;
    fragColor = vec4(0,0,0,0);
    for(float k=1.0; k<3.1; k+=1.0){
        vec2 uv0 = fract(uv*k-0.5) - 0.5;
        float l = length(uv);

        float d = sdStar(uv0, k*0.6, 10,  k*2.0);

        d = abs(sin(d*8.0-iTime/6.0));

        d = (0.05/k) / d;

        // Time varying pixel color
        vec3 col = palette(l-iTime/1.8+length(uv0))*d;

        // Output to screen
        fragColor += vec4(col, 1.0);
    }

}
{% endcapture %}
{% include widgets/shader-embed.html title="Animated shader preview" autoplay="true" start_time="0" shader=about_shader %}

Experiences
: ### Security Engineer @ [Calif.io](https://calif.io/)
: June 2025 - Present
: Working on cool stuffs
: Stay tuned!
: ### Security Research Internship @ [TRAPA Security](https://trapa.tw/)
: *September 2023 - July 2024*
: Extracted and analyzed firmware from multiple IoT devices
: Found a new vulnerability in the Realtek SDK \[[HITCON2024](https://hitcon.org/2024/CMT/agenda/44dc04b6-933f-4418-baee-ff8e3d3f5981/)\]\[[Bside Bloomington](https://bsidesbloomington.org/schedule)\]
: ### Full-stack Developer @ Freelance
: September 2023 - Present
: Designed and developed a full-stack application for [Nippon Signal](https://www.signal.co.jp/)
: ### IT Internship @ [CTS Corporation](https://www.ctscorp.com/)
: *May 2023 - August 2023*
: Integrated existing policy with security standards and identified gaps during security audits
: Used scripting to analyze data from automated network vulnerability scanning tools
: Migrated documentation into a centralized location and created appropriate counterparts for the new systems introduced
: ### Undergraduate Research Assistant @ [Purdue University PurSecLab](https://pursec.cs.purdue.edu/)
: *December 2022 - May 2023*
: Researched control-flow integrity technology in the Linux kernel
: Replicated CVEs in newer kernels using qemu
: ### President @ [B01lers CTF team](https://b01lers.com/)
: *August 2022 - July 2023*
: Placed 10th among all U.S. CTF teams on [CTFtime](https://ctftime.org/team/11464) in 2022
: Arranged callouts and boot camps with 100+ participants
: Introduced advanced security ideas to newcomers in an approachable manner
: ### Teaching Assistant @ [AIS3](https://ais3.org/)
: *July 2022*
: Guided 150 participants in advanced information security lectures
: Assisted 20 participants in generating ideas for security projects related to current technologies
: Enhanced my understanding of modern automobile security and its interactions with surrounding systems

---

Education
: ### Purdue University
: *BS in Cybersecurity \| Class of 2025*
: Graduated with Highest Distinction, GPA 3.99 / 4.0

---

Competition and Awards
: ### [Mitre eCTF 2025](https://ectf.mitre.org/) (with Purdue)
: *February 2025 - May 2025*
: 2nd Place / 139 teams
: ### [International Cybersecurity Challenge](https://icc.ecsc.eu/) (with Team Asia)
: November 2024
: 2nd Place
: ### [HITCON CTF 2024](https://ctf2024.hitcon.org) (with TWN48)
: *July 2024 - November 2024*
: Created [4 challenges](https://github.com/bronson113/My_CTF_Challenges/tree/main/HITCON%20CTF%202024) for the qualifier and [redacted] for the final.
: ### [DEFCON CTF 2024](https://defcon.org/)  (with if this works we'll get less next year)
: *August 2024*
: 7th Place (Final) / 10th Place (Qualifier) / 263 teams
: ### [SECCON CTF 2023](https://ctf.seccon.jp/) (with ${CyStick})
: *September 2023 - December 2023*
: 3rd Place (Final) / 2nd Place (Qualifier) / 653 teams
: ### [HITCON CTF 2023](https://hitcon.org/2023/carnival/CTF/) (with TWN48)
: *August 2023 - November 2023*
: Created [3 challenges](https://github.com/bronson113/My_CTF_Challenges/tree/main/HITCON%20CTF%202023) for the qualifier and 1 challenge for the final
: ### [Mitre eCTF 2023](https://ectf.mitre.org/) (with Purdue)
: *February 2023 - May 2023*
: 6th Place / 80 teams \| Best Poster Award
: ### [CSAW CTF 2022](https://www.csaw.io/ctf) (with B01lers)
: *December 2022*
: 13th Place (Final) / 6th Place (Qualifier) / 880 teams
: ### [DEFCON CTF 2022](https://defcon.org/)  (with 217.balsn@TSJ.tw)
: *August 2022*
: 9th Place (Final) / 2nd Place (Qualifier) / 470 teams
: ### HackIN 2021 (with B01lers)
: *November 2021*
: 3rd Place / 30 teams
: ### [Mitre eCTF 2021](https://ectf.mitre.org/) (with Purdue)
: *February 2021 - May 2021*
: 8th Place / 16 teams
: My implementation: [https://github.com/bronson113/2021-ectf-purdue](https://github.com/bronson113/2021-ectf-purdue)
: ### [HITCON CTF 2020](https://ctf.hitcon.org)  (with Goburin\')
: *December 2020*
: 2nd Place (Final) / 3rd Place (Qualifier) / 710 teams
: ### [AIS3 2019](https://ais3.org/)
: *July 2019*
: Best Project Award


---


Project
: ### [Cute Floating Ghost](https://www.shadertoy.com/view/cdSBWV)
: *July 2023* \| Shader, GLSL, Ray marching
: This animation was created using ray marching and shader math. I drew a ghost that floats and moves in the ocean.
: There will be a blog post about this! Stay tuned!
: ### [Ascii art web server](https://github.com/bronson113/ascii_art_web_server)
: *April 2023 - May 2023* \| Server, Concurrency, OS
: This project created a server with a web interface that takes an image URL and converts it to ASCII art. The server spawns worker threads and distributes incoming connections across them to allow concurrent processing. It also experiments with the new proc_fd interface and the ability to pass file descriptors to a different process.
: ### [Padding Oracle On Custom Padding Methods](/2023/09/08/hitconctf-2023-careless-padding.html)
: *March 2023 - April 2023*  \| Cryptography, Block Cipher
: Discovered an efficient attack method against a novel padding method proposed in [this conference paper](https://link.springer.com/chapter/10.1007/978-3-319-30840-1_21)
: Created a CTF challenge based on the attack method in HITCON CTF
: ### [Vulnerability Explorer](https://github.com/bronson113/vuln_visualizer)
: *January 2023 - Present*   \|  Python, Flask, Compiler \| Note: this project is still in the idea phase
: Visualized execution of vulnerable program graphically for better comprehension
: Implemented a simplified compiler for easy experimentation
: ### [mktmpdir](https://github.com/bronson113/mktmpdir)
: *January 2023* \| Shellscript, Bash
: This is a simple shell script that drops the user into a temporary folder. It allows users to run small experiments without worrying about disrupting their folder structure. The script supports keeping the temporary folder afterward and naming the session.
: ### Raspberry PI Remote Display Server
: *December 2021* \| Python, Flask, LCD display
: Designed interaction between a web server and a hardware LCD screen
: Allowed easy management of remote display with real-time monitoring
: Implemented a simple database for swapping previously displayed images
: ### [Ferris Sweep Keyboard](https://github.com/bronson113/zmk-config)
: *December 2021* \| Micro-controller, Keyboard, Soldering
: I built my own keyboard using the [Ferris Sweep 34-key design](https://github.com/davidphilipbarr/Sweep). I used a [nice-nano](https://nicekeyboards.com/nice-nano/) microcontroller along with the ZMK firmware to support Bluetooth connectivity. The link above points to the ZMK config I used during the build.
: ### [This Blog Website](/)
: *September 2021 - current* \| Jekyll, Markdown, HTML, CSS
: This website was originally created from a [Jekyll blog template](https://chadbaldwin.net/2021/03/14/how-to-build-a-sql-blog.html) by [Chad Baldwin](https://github.com/chadbaldwin). I later expanded it to suit my needs.
: The components updated include:
: - The theme for the navigation bar
: - Tag filter in page archive, taken mostly from [TeXt theme](https://github.com/kitian616/jekyll-TeXt-theme)
: - A separate about-me page
: - Back to top button
: Link to source code: [https://github.com/bronson113/bronson113.github.io](https://github.com/bronson113/bronson113.github.io)
: ### Code Optimization on Pattern Matching Algorithm
: *June 2021* \| C++, Optimization, Cache
: Implemented the FM-index algorithm with ideal time complexity
: Applied optimization such as loop unrolling and compression to minimize cache miss-rate
: Achieved 41x runtime efficiency compared to the naive implementation
: ### Adversarial Example Generator
: *July 2019* \| Machine Learning, Python
: Adversarial examples are inputs that are incorrectly identified by machine learning models. This project aimed to create a model that could automatically generate adversarial examples.
: This project was built at AIS3 2019 and won the Best Project Award.
: ### [Battle Starship](https://bronson113.github.io/battlestarship/)
:  *January 2018*
: This is a minigame made with single-page HTML and JavaScript.
: Credit to [donnie9171](https://scratch.mit.edu/users/donnie9171/) for the original idea and prototype in [Scratch](https://scratch.mit.edu/projects/160599153/).
