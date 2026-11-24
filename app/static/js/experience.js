
import * as THREE from "three";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";

const canvas = document.querySelector("#cyber-scene");
const loading = document.querySelector("#loading");
const loadingText = document.querySelector("#loading-text");
const progressBar = document.querySelector("#progress-bar");

const scene = new THREE.Scene();
scene.background = new THREE.Color("#05080b");
scene.fog = new THREE.Fog("#05080b", 25, 75);

const camera = new THREE.PerspectiveCamera(
    55,
    window.innerWidth / window.innerHeight,
    0.1,
    1000
);

// Verified against the loaded monitor geometry and collision-checked camera route.
const monitorCameraPosition = new THREE.Vector3(2.3, 2.5, 0.8);
const monitorTarget = new THREE.Vector3(4.296, 2.327, 0.235);

// Temporary camera pose before the GLB bounds are available.
camera.position.set(0, 3, 20);
camera.lookAt(0, 2, 0);

const renderer = new THREE.WebGLRenderer({
    canvas,
    antialias: false,
    powerPreference: "low-power"
});

renderer.setSize(window.innerWidth, window.innerHeight);
renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.25));
renderer.outputColorSpace = THREE.SRGBColorSpace;
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.1;

function renderScene() {
    renderer.render(scene, camera);
}

// Lighting
scene.add(new THREE.AmbientLight(0xffffff, 1.7));

const greenLight = new THREE.PointLight(0x9cff55, 35, 35);
greenLight.position.set(0, 6, 5);
scene.add(greenLight);

const blueLight = new THREE.PointLight(0x2879ff, 20, 30);
blueLight.position.set(-8, 4, -5);
scene.add(blueLight);

// Load your actual security room
const loader = new GLTFLoader();

loader.load(
    "/static/model/security-room.glb",

    (gltf) => {
        const room = gltf.scene;
        scene.add(room);

        const bounds = new THREE.Box3().setFromObject(room);
        const center = bounds.getCenter(new THREE.Vector3());
        const size = bounds.getSize(new THREE.Vector3());
        const originalCameraPosition = new THREE.Vector3(
            center.x,
            center.y + 0.5,
            center.z + 18
        );
        const securityDoors = [];

        room.traverse((object) => {
            if (
                object.isMesh &&
                object.name.includes("SecurityDoorFrame_MI_ENV_MAT_Office_01_Door_0")
            ) {
                const doorBounds = new THREE.Box3().setFromObject(object);
                securityDoors.push({
                    bounds: doorBounds,
                    center: doorBounds.getCenter(new THREE.Vector3())
                });
            }
        });

        if (securityDoors.length === 0) {
            console.error("Could not find a security-room door frame in the GLB model.");
            loadingText.textContent = "Could not identify the security-room door.";
            loading.classList.add("loading-error");
            setTimeout(() => {
                loading.classList.add("loading-dismissed");
                setTimeout(() => loading.remove(), 900);
            }, 1600);
            return;
        }

        const door = securityDoors.reduce((nearest, candidate) =>
            candidate.center.distanceToSquared(originalCameraPosition) <
            nearest.center.distanceToSquared(originalCameraPosition)
                ? candidate
                : nearest
        );
        const doorCenter = door.center;
        const cameraStart = originalCameraPosition.clone();
        cameraStart.x = doorCenter.x;

        const approachSide = cameraStart.z >= doorCenter.z ? 1 : -1;
        const doorClearance = 1.25;
        const cameraEnd = new THREE.Vector3(
            doorCenter.x,
            cameraStart.y,
            approachSide > 0
                ? door.bounds.max.z + doorClearance
                : door.bounds.min.z - doorClearance
        );
        const targetStart = new THREE.Vector3(
            doorCenter.x,
            doorCenter.y,
            approachSide > 0
                ? door.bounds.max.z + doorClearance + 1.5
                : door.bounds.min.z - doorClearance - 1.5
        );

        console.log("Security room center:", center);
        console.log("Security room dimensions:", size);
        console.log("Security door bounds:", door.bounds);
        console.log("Camera path:", {
            start: cameraStart,
            end: cameraEnd,
            targetStart,
            targetEnd: doorCenter
        });

        window.securityRoom = room;
        window.securityRoomBounds = bounds;
        window.securityDoorBounds = door.bounds;
        window.securityDoorCenter = doorCenter.clone();
        window.securityCameraPath = {
            start: cameraStart.clone(),
            end: cameraEnd.clone(),
            targetStart: targetStart.clone(),
            targetEnd: doorCenter.clone(),
            monitor: monitorCameraPosition.clone(),
            monitorTarget: monitorTarget.clone()
        };

        camera.position.copy(cameraStart);
        camera.lookAt(targetStart);
        renderScene();

        loadingText.textContent = "Security room loaded successfully";

        setTimeout(() => {
            loading.style.opacity = "0";
            setTimeout(() => loading.remove(), 900);
        }, 500);

        setupScrollAnimation(cameraStart, cameraEnd, targetStart, doorCenter);
    },

    (progress) => {
        if (progress.total > 0) {
            const percent = (progress.loaded / progress.total) * 100;
            loadingText.textContent =
                `Loading security room... ${Math.round(percent)}%`;
        }
    },

    (error) => {
        console.error("GLB loading error:", error);
        loadingText.textContent =
            "The 3D room could not load. You can still explore this page or return home.";
        loading.classList.add("loading-error");
        setTimeout(() => {
            loading.classList.add("loading-dismissed");
            setTimeout(() => loading.remove(), 900);
        }, 1600);
    }
);

// Smooth scroll and camera animation
function setupScrollAnimation(cameraStart, cameraEnd, targetStart, doorCenter) {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        return;
    }

    if (!window.gsap || !window.ScrollTrigger) {
        console.warn("GSAP animation libraries are unavailable; using native scroll.");

        const updateFromScroll = () => {
            const scrollRange = Math.max(
                document.documentElement.scrollHeight - window.innerHeight,
                1
            );
            const progress = Math.min(Math.max(window.scrollY / scrollRange, 0), 1);
            const segmentProgress = progress <= 0.5
                ? progress * 2
                : (progress - 0.5) * 2;

            if (progress <= 0.5) {
                camera.position.lerpVectors(cameraStart, cameraEnd, segmentProgress);
                camera.lookAt(
                    targetStart.clone().lerp(doorCenter, segmentProgress)
                );
            } else {
                camera.position.lerpVectors(
                    cameraEnd,
                    monitorCameraPosition,
                    segmentProgress
                );
                camera.lookAt(
                    doorCenter.clone().lerp(monitorTarget, segmentProgress)
                );
            }
            progressBar.style.height = `${progress * 100}%`;
            renderScene();
        };

        window.addEventListener("scroll", updateFromScroll, { passive: true });
        window.addEventListener("resize", updateFromScroll, { passive: true });
        updateFromScroll();
        return;
    }

    window.gsap.registerPlugin(window.ScrollTrigger);

    if (window.Lenis) {
        const lenis = new window.Lenis({
            duration: 1.3,
            smoothWheel: true,
            wheelMultiplier: 0.8
        });

        lenis.on("scroll", window.ScrollTrigger.update);

        window.gsap.ticker.add((time) => {
            lenis.raf(time * 1000);
        });

        window.gsap.ticker.lagSmoothing(0);
    }

    const cameraPath = {
        x: cameraStart.x,
        y: cameraStart.y,
        z: cameraStart.z,
        targetX: targetStart.x,
        targetY: targetStart.y,
        targetZ: targetStart.z
    };

    const updateCamera = () => {
        camera.position.set(cameraPath.x, cameraPath.y, cameraPath.z);
        camera.lookAt(
            cameraPath.targetX,
            cameraPath.targetY,
            cameraPath.targetZ
        );
        renderScene();
    };

    const timeline = window.gsap.timeline({
        scrollTrigger: {
            trigger: ".journey",
            start: "top top",
            end: "bottom bottom",
            scrub: 1.2
        }
    });

    timeline.to(cameraPath, {
        x: cameraEnd.x,
        y: cameraEnd.y,
        z: cameraEnd.z,
        targetX: doorCenter.x,
        targetY: doorCenter.y,
        targetZ: doorCenter.z,
        ease: "none",
        onUpdate: updateCamera
    });

    timeline.to(cameraPath, {
        x: monitorCameraPosition.x,
        y: monitorCameraPosition.y,
        z: monitorCameraPosition.z,
        targetX: monitorTarget.x,
        targetY: monitorTarget.y,
        targetZ: monitorTarget.z,
        ease: "none",
        onUpdate: updateCamera
    });

    // Page progress indicator
    window.gsap.to(progressBar, {
        height: "100%",
        ease: "none",
        scrollTrigger: {
            trigger: ".journey",
            start: "top top",
            end: "bottom bottom",
            scrub: true
        }
    });
}

// Render only when the camera or viewport changes.
window.addEventListener("resize", () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();

    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.25));
    renderScene();
});
