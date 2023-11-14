/**
 * 
 * @param {string} cname 
 * @param {string} cvalue 
 * @param {number} exdate 
 */
export function setCookie(cname, cvalue, exdate) {
  const d = new Date();
  d.setTime(exdate);
  let expires = "expires=" + d.toUTCString();
  document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
}

/**
 * 
 * @param {string} cname 
 * @returns {string}
 */
export function getCookie(cname) {
  let name = cname + "=";
  let decodedCookie = decodeURIComponent(document.cookie);
  let ca = decodedCookie.split(";");
  for (let i = 0; i < ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) == " ") {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
}
