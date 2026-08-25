/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

(function () {
	'use strict';
	document.querySelectorAll('.trace').forEach(function (trace) {
		var rows = Array.prototype.slice.call(trace.querySelectorAll('[data-step]'));
		if (rows.length === 0) {
			return;
		}
		function span(el) {
			var parts = el.getAttribute('data-step').split('-');
			var a = parseInt(parts[0], 10);
			var b = parts.length > 1 ? parseInt(parts[1], 10) : a;
			return [a, b];
		}
		function clear() {
			rows.forEach(function (row) {
				row.classList.remove('isOn');
			});
		}
		rows.forEach(function (row) {
			row.addEventListener('mouseenter', function () {
				var mine = span(row);
				rows.forEach(function (other) {
					var theirs = span(other);
					other.classList.toggle('isOn', mine[0] <= theirs[1] && theirs[0] <= mine[1]);
				});
			});
			row.addEventListener('mouseleave', clear);
		});
	});
})();
