.. _decorator-chapter:

====================================
Modifying the Policy with Decorators
====================================

Content Security Policies should be restricted and paranoid by default.  You may, on some views,
need to expand or change the policy. django-csp includes four decorators to help.

All decorators take an optional keyword argument, ``REPORT_ONLY``, which defaults to ``False``. If
set to ``True``, the decorator will update the report-only policy instead of the enforced policy.

``@csp_exempt``
===============

Using the ``@csp_exempt`` decorator disables the CSP header on a given
view.

.. code-block:: python

    from csp.decorators import csp_exempt


    # Will not have a CSP header.
    @csp_exempt()
    def myview(request):
        return render(...)


    # Will not have a CSP report-only header.
    @csp_exempt(REPORT_ONLY=True)
    def myview(request):
        return render(...)

You can manually set this on a per-response basis by setting the ``_csp_exempt``
or ``_csp_exempt_ro`` attribute on the response to ``True``:

.. code-block:: python

    # Also will not have a CSP header.
    def myview(request):
        response = render(...)
        response._csp_exempt = True
        return response


``@csp_update``
===============

The ``@csp_update`` header allows you to **append** values to the source lists specified in the
settings. If there is no setting, the value passed to the decorator will be used verbatim.

.. note::

   To quote the CSP spec: "There's no inheritance; ... the default list is not used for that
   resource type" if it is set. E.g., the following will not allow images from 'self':

    default-src 'self'; img-src imgsrv.com

The arguments to the decorator are the same as the :ref:`settings <configuration-chapter>`. The
decorator expects a single dictionary argument, where the keys are the directives and the values
are either strings, lists or tuples. An optional argument, ``REPORT_ONLY``, can be set to ``True``
to update the report-only policy instead of the enforced policy.

.. code-block:: python

    from csp.decorators import csp_update


    # Will append imgsrv.com to the list of values for `img-src` in the enforced policy.
    @csp_update({"img-src": "imgsrv.com"})
    def myview(request):
        return render(...)


    # Will append cdn-img.com to the list of values for `img-src` in the report-only policy.
    @csp_update({"img-src": "cdn-img.com"}, REPORT_ONLY=True)
    def myview(request):
        return render(...)


``@csp_replace``
================

The ``@csp_replace`` decorator allows you to **replace** a source list specified in settings. If
there is no setting, the value passed to the decorator will be used verbatim. (See the note under
``@csp_update``.) If the specified value is None, the corresponding key will not be included.

The arguments and values are the same as ``@csp_update``:

.. code-block:: python

    from csp.decorators import csp_replace


    # Will allow images only from imgsrv2.com in the enforced policy.
    @csp_replace({"img-src": "imgsrv2.com"})
    def myview(request):
        return render(...)


    # Will allow images only from cdn-img2.com in the report-only policy.
    @csp_replace({"img-src": "cdn-img2.com"}, REPORT_ONLY=True)
    def myview(request):
        return render(...)

The ``csp_replace`` decorator can also be used to remove a directive from the policy by setting the
value to ``None``. For example, if the ``frame-ancestors`` directive is set in the Django settings
and you want to remove the ``frame-ancestors`` directive from the policy for this view:

.. code-block:: python

    from csp.decorators import csp_replace


    @csp_replace({"frame-ancestors": None})
    def myview(request):
        return render(...)


``@csp``
========

If you need to set the entire policy on a view, ignoring all the settings, you can use the ``@csp``
decorator. This can be stacked to update both the enforced policy and the report-only policy if both
are in use, as shown below.

.. code-block:: python

    from csp.constants import SELF, UNSAFE_INLINE
    from csp.decorators import csp


    @csp(
        {
            "default-src": [SELF],
            "img-src": ["imgsrv.com"],
            "script-src": ["scriptsrv.com", "googleanalytics.com", UNSAFE_INLINE],
        }
    )
    @csp(
        {
            "default-src": [SELF],
            "img-src": ["imgsrv.com"],
            "script-src": ["scriptsrv.com", "googleanalytics.com"],
            "frame-src": [SELF],
        },
        REPORT_ONLY=True,
    )
    def myview(request):
        return render(...)


Conditional updates inside a view
=================================

Decorators are convenient when the policy change is known while defining the
view. For values that are only known after rendering or hashing a response, set
the same response attribute that the decorator would have set:

.. code-block:: python

    def myview(request):
        # Compute this from the exact inline <script> body, without the tags.
        script_hash = "sha256-..."
        response = render(request, "inline.html")
        response._csp_update = {"script-src": [f"'{script_hash}'"]}
        return response

Use ``_csp_update_ro`` for a report-only addition. The middleware still builds
and writes the header once, so the view-provided hash and request nonce end up
in the same directive.


Headers written directly by views
=================================

If a view or another WSGI component sets ``Content-Security-Policy`` before
``CSPMiddleware`` processes the response, the middleware parses that header and
merges it with the policy generated from settings and response attributes. This
avoids emitting two policy headers.

The default ``"compose"`` mode combines source lists and resolves
``default-src`` and the more specific fallback chains before merging. A sole
``'none'`` value and an empty ``sandbox`` remain strict, sandbox permission
tokens are intersected, reporting endpoints are combined, and
``'unsafe-inline'`` is removed when a nonce or hash is also present.

Because composing two independently complete policies can be more permissive
than letting the browser enforce both headers, subclasses can select the
browser-like intersection mode:

.. code-block:: python

    class StrictCSPMiddleware(CSPMiddleware):
        existing_header_merge_mode = "strict"

In strict mode, source expressions that are not present on both sides become
``'none'`` after fallback resolution. Prefer ``_csp_update`` when a view has a
hash or other exception that must be included in the generated policy rather
than intersected with it.

To restore the previous behavior of leaving a response-provided header
completely untouched:

.. code-block:: python

    class PreserveViewCSPMiddleware(CSPMiddleware):
        merge_existing_headers = False
