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

Offsensive Security Engineer @ [Calif.io](https://calif.io).

B.S. Cybersecurity @ Purdue University.

Former President of [b01lers](https://b01lers.com) @ Purdue.

Active member of Taiwanese CTF Team ${CyStick} and TSJ. Part of TWN48.

I specialize in **Pwnable**, **Crypto**, and all kinds of miscellaneous challenges.

I enjoy researching cool tricks and quirks in various computing systems and languages, as well as optimizing things with thoughtful techniques and algorithms.

<span style="color:grey">*Animation - recreated from [Shadertoy source](https://www.shadertoy.com/view/cdBcWV).*</span>
