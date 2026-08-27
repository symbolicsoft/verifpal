/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

(function () {
	'use strict';

	function span(el) {
		var parts = el.getAttribute('data-step').split('-');
		var a = parseInt(parts[0], 10);
		var b = parts.length > 1 ? parseInt(parts[1], 10) : a;
		return [a, b];
	}

	function pressable(el) {
		return el.hasAttribute('aria-pressed');
	}

	document.querySelectorAll('.trace').forEach(function (trace) {
		var rows = Array.prototype.slice.call(trace.querySelectorAll('[data-step]'));
		if (rows.length === 0) {
			return;
		}
		var pinned = null;
		function paint(row) {
			var mine = row === null ? null : span(row);
			rows.forEach(function (other) {
				var theirs = span(other);
				var on = mine !== null && mine[0] <= theirs[1] && theirs[0] <= mine[1];
				other.classList.toggle('isOn', on);
				if (pressable(other)) {
					other.setAttribute('aria-pressed', other === pinned ? 'true' : 'false');
				}
			});
		}
		function show(row) {
			paint(row === null ? pinned : row);
		}
		rows.forEach(function (row) {
			row.addEventListener('mouseenter', function () {
				show(row);
			});
			row.addEventListener('mouseleave', function () {
				show(null);
			});
			row.addEventListener('focusin', function () {
				show(row);
			});
			row.addEventListener('focusout', function () {
				show(null);
			});
			if (!pressable(row)) {
				return;
			}
			row.addEventListener('click', function () {
				pinned = pinned === row ? null : row;
				show(null);
			});
		});
	});

	document.querySelectorAll('section.model').forEach(function (model) {
		var values = Array.prototype.slice.call(model.querySelectorAll('.msgVal[data-q]'));
		if (values.length === 0) {
			return;
		}
		var tagged = values.map(function (value) {
			return value.getAttribute('data-q').split(' ');
		});
		function isolate(index) {
			values.forEach(function (value, i) {
				var mine = index !== null && tagged[i].indexOf(index) >= 0;
				value.classList.toggle('isHit', mine);
				value.classList.toggle('isDim', index !== null && !mine);
			});
		}
		model.querySelectorAll('.verdict[data-query]').forEach(function (verdict) {
			var index = verdict.getAttribute('data-query');
			function on() {
				isolate(index);
			}
			function off() {
				isolate(null);
			}
			verdict.addEventListener('mouseenter', on);
			verdict.addEventListener('mouseleave', off);
			verdict.addEventListener('focusin', on);
			verdict.addEventListener('focusout', off);
		});
	});

	var only = document.getElementById('onlyFailing');
	if (only) {
		only.addEventListener('change', function () {
			var hide = only.checked;
			document
				.querySelectorAll('.runItem[data-failing], section.model[data-failing]')
				.forEach(function (el) {
					el.hidden = hide && el.getAttribute('data-failing') !== 'yes';
				});
		});
	}

	var reopen = [];
	window.addEventListener('beforeprint', function () {
		reopen = [];
		document.querySelectorAll('details.traceGroup').forEach(function (group) {
			if (!group.open) {
				reopen.push(group);
				group.open = true;
			}
		});
	});
	window.addEventListener('afterprint', function () {
		reopen.forEach(function (group) {
			group.open = false;
		});
		reopen = [];
	});
})();
