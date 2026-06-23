// _scramble.js - local copy
const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%@*/!&";
const getRandomChar = () => chars[Math.floor(Math.random() * chars.length)];
const scrambleNode = $element => {
  if (!$element.data('originalText')) $element.data('originalText', $element.text());
  clearInterval($element.data('scrambleInterval'));
  let iteration = 0;
  const originalText = $element.data('originalText');
  const interval = setInterval(() => {
    $element.text(originalText.split("").map(char => char === " " ? char : getRandomChar()).join(""));
    if (++iteration >= 10) { clearInterval(interval); $element.text(originalText); $element.removeData('scrambleInterval'); }
  }, 35);
  $element.data('scrambleInterval', interval);
};
$('[scramble]').on('mouseenter', function () {
  $(this).find('*').addBack().contents().filter(function () {
    return this.nodeType === 3 && this.textContent.trim() && !$(this).parent().children().length && !$(this).parent().closest('[no-scramble]').length;
  }).parent().each((_, el) => scrambleNode($(el)));
});
$('[scramble]').on('mouseleave', function () {
  $(this).find('*').addBack().each((_, el) => {
    const $el = $(el); clearInterval($el.data('scrambleInterval'));
    if ($el.data('originalText')) { $el.text($el.data('originalText')); $el.removeData('scrambleInterval'); }
  });
});