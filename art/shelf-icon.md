# Held Light

*An algorithmic philosophy for the shelf icon.*

A shelf is a cage that looks friendly. Its uprights hold things in place the way bars do, and
from the right distance nobody can tell a row of spines from a row of bars. Held Light lives in
that ambiguity: a handful of vertical bodies stand on one horizontal line, and the eye decides
whether it is looking at a library or an enclosure. The work never settles the question. It is
the product of deep computational patience, every proportion argued over until the row reads
as both at once and as neither.

The system is a small society of rectangles. A seeded generator, deterministic to the bit,
draws how many bodies stand on the line, how wide each one is and how much height it is
allowed. Heights do not come from independent dice; they come from a smooth one-dimensional
noise walked across the row, so neighbours resemble neighbours the way real spines do, and the
silhouette rises and falls like a skyline rather than a bar chart. The widths are weights that
are normalised against the space available, so the row always fills its frame exactly, with
gaps that stay constant while everything around them varies. This is a meticulously balanced
algorithm: crowd it and it becomes a barcode, thin it and it becomes a fence, and the parameter
ranges were narrowed, iteration after iteration, to the narrow band where it is a shelf.

One body refuses to stand. The last spine leans, and the lean is not decorative: its angle is
solved, not chosen. The algorithm places its foot a seeded distance from its neighbour and
computes the exact tilt at which its face touches the neighbour's top corner, then lengthens the
leaning body if it would otherwise fall short. Gravity is satisfied analytically. That single
solved contact is the emotional centre of the piece, a moment of rest inside a rigid order,
and it should feel like the product of master-level care: nothing in the frame is placed by
hand, yet nothing looks accidental.

Light is the last force. Behind the row a radial field glows from the shelf line, so the bodies
read as dark against a dim warmth that is kept inside them, never spilling to the frame's edge.
One spine, chosen by the seed, catches more of that light than the rest, the one most recently
taken down and put back. Colour is restricted to a single grey ramp from near-black to
near-white: the palette is discipline, and depth comes only from value. Fine vertical grain,
born from the same noise, appears inside each spine at large sizes and vanishes as the canvas
shrinks, because an icon must survive being sixteen pixels tall. Painstaking optimisation went
into that survival: the composition is judged at its smallest size first.

Every seed is a different shelf and the same idea. The algorithm is the artwork; any single
frame is one print pulled from it. What matters is the process that solves balance, spacing and
contact the same way every time it runs, a quiet piece of computational craftsmanship that
should look as if it took a very long time to get right, because it did.
