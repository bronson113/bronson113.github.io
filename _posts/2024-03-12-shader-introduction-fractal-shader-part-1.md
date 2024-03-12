---
title: Ray Marching Introduction - Floating Ghost
tag:
- Graphics
- Shaders
---

# Shader Introduction - Fractal Shader (Part 1 /???)

## Introduction

Over the past few weeks, I grow interest in shader. I love how that complicated patterns can be created from simple, concised code. 
I was watching YouTube mindlessly and found several wounderful tutorials that teach me the basics of shader, and that's how I get started. I'll link those tutorials along the way and at the end of this artical.

<!--more-->

This blog post will try to note down the sources I used for each section, along with my reasoning behind doing each part.

### Shadertoy
Before we start, I'll shall introduce the tools we'll be using. This tutorial will be mainly through [shadertoy](https://www.shadertoy.com/). This is a website that interfaces with webgl using GLSL, the opengl shading language. This allow the user to swiftly iterates through ideas using a simple interface. 

You can press Alt+Enter to compile the current code. This will be very useful, so you don't need to reach for the mouse to see your progress.
## What is shader
That's start with the basics, what is shader?

In my understanding, shader is a program that is:
1. Applied to each pixel
2. Independent to other pixel
3. Returns a color that should be displayed on that pixel

This means that each pixel is essesntially its own unit. and we can exploit that high level of parallelism using something like a GPU.

> I understand that this definition is probably a bit off for general graphics with vertex shaders and stuff, but we'll use this definition for now.

Lets take for example. If the shader is as follows (In pseudocode)

```
color shader(pixel_x, pixel_y):
    return (pixel_x, pixel_y, 0.0)
```

It will take each pixel separatedly, assign the pixel's x coordinate to the red channel, the y coordinate to the green channel, and return the color. With every pixel colored, you get something like the following.

<iframe width="100%" height="360" frameborder="0" src="https://www.shadertoy.com/embed/dt2czD?gui=false&t=0&paused=true" allowfullscreen></iframe>

{% capture shader_example %}
```js
void mainImage( out vec4 fragColor, in vec2 fragCoord )
{
    fragColor = vec4(fragCoord.xy/200.0, 0.0, 1.0);
}
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="shader_example" button-text="Show shader code" toggle-text=shader_example %}

That's not too bad right? You just use the coordinate to calculate some value, and that will be the color of that pixel. 
### Coordinate & Color System
If you actual checked what's written in the shader above, you'll notice that there is a weird divide by 200 in the code. It's about time to introduce the coordinate system in shader toy.

By default, shader toy labels the pixels from the bottom left cornor, and utilized the standard math axis direction. So right is the +x direction and up is the +y direction. Each pixel will be a width of 1, so each pixel will get a integer coordinate. 

Next, shader toy interpretes the return value for mainImage as a tuple of RGBA, each ranging from 0.0 to 1.0. However, the transprancy value is dropped when rendering. The value of each color is clamped to 0.0 to 1.0, so value larger then 1 will rander with full brightness, while a negative value will render as black.

### Normalize Coordinate
In order to better work with the canvas, we'll like to set the coordinate such that the origin is in the middle of the screen, and range from -1 to 1 from the left side to the right side (Or from top to bottom). This can be done by scaling and shifting to coordinate.

First, moving the origin to the center of the screen can simply be done by subtracting the coordinate by half the screen size. 
```
vec2 centered = fragCoord.xy - iResolution.xy/2.; 
```
Here, fragCoord is the pixel coordinate, and iResolution is a varible provided by shader toy to reference the currect render screen size.

If we now think of the center of the screen. The fragCoord will be half the screen resolution in both axis. Now that we subtract half the resolution, the "centered" variable now holds (0, 0). The same logic applies to all other points, and this indeed center the coordinate system.

The next thing is to fix the coordinate, so the same / similar enough image is displayed on different screen resolution. For our case, we want that the coordinate span from -1 to 1 no matter how large the screen is. This is simple, we can just stretch the coordinate by the resolution, half the resolution infact. Something to consider is that whether we want to the result to stretch when the aspect ratio changed. Some might what it to just truncate out the part, but it sometimes also make sense to stretch the whole image.

If we want to aspect ratio to be fix to 1:1, which is the most common, we need to divide the centered coordinate by iResolution.y. 
Note that we use the y coordinate since it's usually the shorter coordinate, and the main image part will also be shown without the trancation. 

However, since each pixel can't talk to each other, how to they collectively form a picture? The trick is some math!

## Math (Yes! MATH!)
### Circles
You might think: Why are math relavent here? Well, when we think of a picture, we see shapes and graphs. Each shapes can then be translated into a kind of equation. Think of a circle. It's basically taking all the points such that the distance to the center is smaller than a threashold. For example, a circle of radius 1 is formed with $x^2 + y^2 \leq 1$. 

Now, if we reverse that process, and try to determine if a point is in a circle, then each individual points can collectivly draw a circle. This can be done by calculating the distance of each point to the center, then check if that distance is less than 1! In fact, this can be generalized further. For any shape that we need to draw, we can find the formula that determines how far this point is from the shape. Actually to better distingush the inside of the shape from the outside, we'll try to make the formula produce negative distance if it's inside the shape. This distance function is called the Signed Distance Function, or SDF for short. We can find the SDF for various shapes and use those to draw the shapes we want.

<iframe width="100%" height="360" frameborder="0" src="https://www.shadertoy.com/embed/M3SXRh?gui=false&t=0&paused=true" allowfullscreen></iframe>

{% capture shader_example_2 %}
```js
float sdf_circle(vec2 coordinate, vec2 center, float radius){
    return length(coordinate - center) - radius;
}


void mainImage( out vec4 fragColor, in vec2 fragCoord )
{
    // Normalized pixel coordinates (from -1 to 1 on the y axis)
    vec2 uv = (2.*fragCoord - iResolution.xy) / iResolution.y ;

    // draw a circle center at (0, 0) with radius of 0.5
    vec2 center = vec2(0., 0.);
    float dist = sdf_circle(uv, center, .5);
    vec3 col = vec3(dist);

    // Output to screen
    fragColor = vec4(col,1.0);
}
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="shader_example_2" button-text="Show shader code" toggle-text=shader_example_2 %}

One really helpful resource I found is [Inigo Quilez's website](https://iquilezles.org/). He had various articles on shader as well as some wiki type blog that acted like a dictionary. For example, there is a [page](https://iquilezles.org/articles/distfunctions2d/) that contains a lot of SDF for various shapes along with demos and code. It is a great resource for both learning shader and various techniques in rendering.

### Creating Edges
In the previous example, the center black part is where the SDF returns a negative number, and the outer gray-ish part is where it returns a positive number. However, we might only want to draw the circumference of the circule. One way is to use comparisons, like the following code.
```js
float distance = sdf_circle(...);
if(distance < 0.05 and distance > -0.05) {
    col = vec3(1.);
}
```

However, there are some other math tools we can use to get a smoother result. Firstly, if we're just drawing a ring, the distance to the circumference is probably more useful than the sign distance, so taking the absolute value will help simplify the situation. 

Now we only want the part that is close to 0. The smoothstep function is a suitable candidate here. Firstly, what is a smoothstep function? We know a step function is a function that jumps from 0 to 1 at a certain value.

$$
step(x, v)  = \begin{cases}
    0, &\quad\text{if} x < v \\ 
		1, &\quad\text{if} x \ge v 
\end{cases}
$$

But we want a smoother transition between 0 and 1, so smoothstep comes in handy. It instead now takes three parameters.

$$
smoothstep(st, ed, x)  = \begin{cases}
    0, &\quad\text{if }  x < st \\ 
		f(x), &\quad\text{if } st \le x < ed  \\ 
    1, &\quad\text{if } x \ge ed
\end{cases}
$$

where f(x) is a smooth transition between 0 and 1. There are a lot of different smoothstep functions, but in case of the smoothstep function in [GLSL](https://registry.khronos.org/OpenGL-Refpages/gl4/html/smoothstep.xhtml), the function is $f(x) = x^{2} \times (3 - 2 x)$.

So if we use smootstep to clamp our value around 0.05, we get black circle on white background, since only the part that's close to our center circle gets value close to 0. If we want to invert the color, simply subtracts it from 1, and we get the following.

<iframe width="100%" height="360" frameborder="0" src="https://www.shadertoy.com/embed/M3SXzh?gui=false&t=10&paused=true" allowfullscreen></iframe>

{% capture shader_example_3 %}
```js
float sdf_circle(vec2 coordinate, vec2 center, float radius){
    return length(coordinate - center) - radius;
}


void mainImage( out vec4 fragColor, in vec2 fragCoord )
{
    // Normalized pixel coordinates (from -1 to 1 on the y axis)
    vec2 uv = (2.*fragCoord - iResolution.xy) / iResolution.y ;

    // draw a circle center at (0, 0) with radius of 0.5
    vec2 center = vec2(0., 0.);
    float dist = sdf_circle(uv, center, .5);
    vec3 col = 1. - vec3(smoothstep(0., 0.05, abs(dist)));

    // Output to screen
    fragColor = vec4(col,1.0);
}
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="shader_example_3" button-text="Show shader code" toggle-text=shader_example_3 %}

## Conclusion
Now with the power of math and shader magic, we draw a circle! How exciting right. We'll start getting into more complex part of shader starting with the next part of this series. I'm hoping that this tutorial helps kick start the motivation in shader, and overcome the hard part of getting into this rather foreign form of programming.

Next part: Coming soon...
