import requests

def get_file_by_url(url, params=None, **kwargs):
    """
    Parameters are passed to the requests.get() function.

    Parameters
    ----------
    url : str or bytes
        URL for the new Request object.
    params :
        Dictionary, list of tuples or bytes to send in the query string for the Request.
    kwargs :
        Optional arguments that request takes.

    Returns
    -------
    url_data : str or None
        The data retrieved at that URL from the file. Returns None if the
        attempted retrieval is unsuccessful.
    """

    try:
        req = requests.get(url=url, params=params, **kwargs)
    except requests.exceptions.RequestException:
        print("Error retrieving data from {}".format(url))
        return None

    req.encoding = req.apparent_encoding
    res_text = "\n".join([domain_to_idna(line) for line in req.text.split("\n")])
    return res_text

