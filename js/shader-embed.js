(function () {
  const vertexSource = `#version 300 es
in vec2 a_position;

void main() {
  gl_Position = vec4(a_position, 0.0, 1.0);
}`;

  function compileShader(gl, type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);

    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      const info = gl.getShaderInfoLog(shader);
      gl.deleteShader(shader);
      throw new Error(info || "Shader compilation failed.");
    }

    return shader;
  }

  function createProgram(gl, fragmentSource) {
    const program = gl.createProgram();
    const vertexShader = compileShader(gl, gl.VERTEX_SHADER, vertexSource);
    const fragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, fragmentSource);

    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);

    gl.deleteShader(vertexShader);
    gl.deleteShader(fragmentShader);

    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      const info = gl.getProgramInfoLog(program);
      gl.deleteProgram(program);
      throw new Error(info || "Program linking failed.");
    }

    return program;
  }

  function buildFragmentSource(source) {
    return `#version 300 es
precision highp float;

uniform vec3 iResolution;
uniform float iTime;
uniform float iTimeDelta;
uniform float iFrameRate;
uniform int iFrame;
uniform vec4 iMouse;
uniform vec4 iDate;

out vec4 outColor;

void mainImage(out vec4 fragColor, in vec2 fragCoord);

${source}

void main() {
  vec4 color = vec4(0.0);
  mainImage(color, gl_FragCoord.xy);
  outColor = color;
}`;
  }

  function updateStatus(node, message) {
    node.textContent = message;
    node.hidden = !message;
  }

  function setupEmbed(root) {
    const canvas = root.querySelector(".shader-embed__canvas");
    const status = root.querySelector(".shader-embed__status");
    const sourceNode = root.querySelector(".shader-embed__source");
    const autoplay = root.dataset.autoplay === "true";
    const startTime = Number.parseFloat(root.dataset.startTime || "0") || 0;
    const shaderSource = (sourceNode && sourceNode.textContent) ? sourceNode.textContent.trim() : "";

    if (!canvas || !status || !shaderSource) {
      return;
    }

    const gl = canvas.getContext("webgl2", { antialias: true, alpha: false });

    if (!gl) {
      updateStatus(status, "WebGL2 is not available in this browser.");
      return;
    }

    let program;
    try {
      program = createProgram(gl, buildFragmentSource(shaderSource));
    } catch (error) {
      updateStatus(status, "Shader failed to compile.");
      console.error(error);
      return;
    }

    const positionLocation = gl.getAttribLocation(program, "a_position");
    const resolutionLocation = gl.getUniformLocation(program, "iResolution");
    const timeLocation = gl.getUniformLocation(program, "iTime");
    const timeDeltaLocation = gl.getUniformLocation(program, "iTimeDelta");
    const frameRateLocation = gl.getUniformLocation(program, "iFrameRate");
    const frameLocation = gl.getUniformLocation(program, "iFrame");
    const mouseLocation = gl.getUniformLocation(program, "iMouse");
    const dateLocation = gl.getUniformLocation(program, "iDate");

    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([
        -1, -1,
         1, -1,
        -1,  1,
        -1,  1,
         1, -1,
         1,  1,
      ]),
      gl.STATIC_DRAW
    );

    gl.useProgram(program);
    gl.enableVertexAttribArray(positionLocation);
    gl.vertexAttribPointer(positionLocation, 2, gl.FLOAT, false, 0, 0);

    let frame = 0;
    let startNow = performance.now();
    let lastTime = startNow;
    let animationFrameId = null;
    let resizeObserver = null;

    function resizeCanvas() {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      const width = Math.max(1, Math.floor(canvas.clientWidth * ratio));
      const height = Math.max(1, Math.floor(canvas.clientHeight * ratio));

      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }

      gl.viewport(0, 0, canvas.width, canvas.height);
    }

    function render(now) {
      resizeCanvas();

      const elapsedSeconds = (now - lastTime) / 1000;
      const shaderTime = autoplay ? startTime + ((now - startNow) / 1000) : startTime;
      const frameRate = elapsedSeconds > 0 ? 1 / elapsedSeconds : 60;
      const date = new Date();
      const secondsToday = (
        date.getHours() * 3600 +
        date.getMinutes() * 60 +
        date.getSeconds() +
        date.getMilliseconds() / 1000
      );

      gl.useProgram(program);
      gl.uniform3f(resolutionLocation, canvas.width, canvas.height, 1);
      gl.uniform1f(timeLocation, shaderTime);
      gl.uniform1f(timeDeltaLocation, elapsedSeconds);
      gl.uniform1f(frameRateLocation, frameRate);
      gl.uniform1i(frameLocation, frame);
      gl.uniform4f(mouseLocation, 0, 0, 0, 0);
      gl.uniform4f(dateLocation, date.getFullYear(), date.getMonth() + 1, date.getDate(), secondsToday);
      gl.drawArrays(gl.TRIANGLES, 0, 6);

      lastTime = now;
      frame += 1;

      if (autoplay) {
        animationFrameId = window.requestAnimationFrame(render);
      }
    }

    if (window.ResizeObserver) {
      resizeObserver = new ResizeObserver(resizeCanvas);
      resizeObserver.observe(canvas);
    } else {
      window.addEventListener("resize", resizeCanvas);
    }

    updateStatus(status, "");
    render(performance.now());
  }

  document.querySelectorAll(".js-shader-embed").forEach(setupEmbed);
})();
