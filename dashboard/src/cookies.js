/**
 * 
 * @param {string} cname 
 * @param {string} cvalue 
 * @param {number} exdate 
 */
export function setCookie(cname, cvalue) {
  localStorage.setItem(cname, cvalue);
  // const d = new Date();
  // d.setTime(exdate);
  // let expires = "expires=" + d.toUTCString();
  // document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
}

export function deleteCookie(cname) {
  localStorage.removeItem(cname);
}

/**
 * 
 * @param {string} cname 
 * @returns {string}
 */
export function getCookie(cname) {
  if (localStorage.getItem(cname)) {
    return localStorage.getItem(cname);
  }

  // if cookie is not found in local storage, check document.cookie

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
