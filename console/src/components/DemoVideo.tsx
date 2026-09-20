// The demo video, in the slot on the public page.
//
// It autoplays muted. Muted is not a preference: every browser blocks an unmuted autoplay,
// and a play button that silently does nothing is worse than no autoplay at all. The
// caption says so, and links to YouTube for anyone who wants sound.
//
// The iframe is mounted only once the section scrolls into view, so the page does not
// load a video player — or start playing to nobody — while the reader is still at the top.

import { useEffect, useRef, useState } from "react";

const VIDEO_ID = "UeyZnTPyJDg";

export const WATCH_URL = `https://youtu.be/${VIDEO_ID}`;

const EMBED_URL =
  `https://www.youtube-nocookie.com/embed/${VIDEO_ID}` +
  "?autoplay=1&mute=1&playsinline=1&rel=0&modestbranding=1";

const POSTER_URL = `https://i.ytimg.com/vi/${VIDEO_ID}/maxresdefault.jpg`;

export function DemoVideo() {
  const frame = useRef<HTMLDivElement>(null);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    const node = frame.current;
    if (!node) return;
    // Without the observer the video simply plays from the start, which is the same
    // outcome a beat earlier — never a frame that stays blank.
    if (typeof IntersectionObserver === "undefined") {
      setPlaying(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setPlaying(true);
          observer.disconnect();
        }
      },
      { threshold: 0.3 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return (
    <div className="demo-frame" ref={frame}>
      {playing ? (
        <iframe
          className="demo-video"
          src={EMBED_URL}
          title="KILLSWITCH — a leaked AWS key, contained in one approval"
          allow="autoplay; encrypted-media; picture-in-picture; web-share"
          allowFullScreen
        />
      ) : (
        <>
          <img className="demo-poster" src={POSTER_URL} alt="" />
          <span className="demo-play" aria-hidden="true">
            &#9654;
          </span>
        </>
      )}
    </div>
  );
}
