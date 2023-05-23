(in-package :cl-user)

(defpackage copilot-chat-api
  (:use cl woo dexador ironclad jzon)
  (:export :start-server :stop-server :defextension :send-message))

(in-package :copilot-chat-api)

(defvar *extensions* (make-hash-table :test 'equal))

(defvar *github-secret* "my-github-secret")

(defun verify-github-signature (payload signature)
  (let* ((key (make-hex-byte-array (length *github-secret*)))
         (hmac (make-hmac :sha1 key)))
    (setf (hmac-key hmac) *github-secret*)
    (let ((expected-signature (format nil "sha1=~A" (byte-array-to-hex-string (hmac-digest hmac payload)))))
      (secure-equal signature expected-signature))))

(defun handle-message (message context)
  (let ((response (format nil "You said: ~A" message)))
    (send-message response context)))

(defun handle-github-message (payload context)
  (let* ((signature (getf (ironclad:parse-headers (getf context :headers)) "X-Hub-Signature"))
         (event-type (getf (ironclad:parse-headers (getf context :headers)) "X-GitHub-Event")))
    (when (and signature event-type (verify-github-signature payload signature))
      (let* ((data (decode-json payload))
             (message (format nil "Received GitHub event: ~A" event-type)))
        (send-message message context)))))


(defmacro defextension (name &key handler description icon)
  `(setf (gethash ,name *extensions*)
         (list :handler ,handler
               :description ,description
               :icon ,icon)))

(defun send-message (message context)
  (let ((response (encode-json `(:message ,message :context ,context))))
    (let ((url (getf context :url))
          (headers (list (cons "Content-Type" "application/json"))))
      (dex:get url :headers headers :body response :ssl-p t))))

(defun handle-request (request)
  (let* ((payload (ironclad:receive-body request))
         (content-type (getf (ironclad:parse-headers (getf request :headers)) "Content-Type"))
         (context (decode-json (getf request :parameters))))
    (cond ((and payload content-type (string= content-type "application/json"))
           (handle-github-message payload context))
          ((and payload context)
           (let ((message (decode-json payload)))
             (funcall (gethash (getf context :extension) *extensions*) :handler message context))))
    (woo:send-response request "")))

(defun start-server (port)
  (woo:start #'handle-request :port port :ssl-p t))

(defun stop-server ()
  (woo:stop))

(defun send-github-webhook (url payload)
  (let* ((signature (format nil "sha1=~A" (byte-array-to-hex-string (hmac-digest (make-hmac :sha1 (make-hex-byte-array (length *github-secret*))) *github-secret* payload))))
         (headers (list (cons "Content-Type" "application/json") (cons "X-Hub-Signature" signature))))
    (dex:get url :headers headers :body payload :ssl-p t)))

(defun authenticate-github-user (code client-id client-secret redirect-uri)
  (let* ((url (format nil "https://github.com/login/oauth/access_token?client_id=~A&client_secret=~A&code=~A&redirect_uri=~A" client-id client-secret code redirect-uri))
         (response (dex:get url :ssl-p t))
         (params (parse-query-string response)))
    (getf params "access_token")))

(defun get-github-user (access-token)
  (let* ((url (format nil "https://api.github.com/user?access_token=~A" access-token))
         (response (dex:get url :headers (list (cons "User-Agent" "Copilot-Chat-API")) :ssl-p t)))
    (decode-json response)))

(defun send-message-to-github-issue (owner repo issue-number message access-token)
  (let* ((url (format nil "https://api.github.com/repos/~A/~A/issues/~A/comments" owner repo issue-number))
         (payload (encode-json `(:body ,message)))
         (headers (list (cons "Content-Type" "application/json") (cons "Authorization" (format nil "token ~A" access-token))) ))
    (dex:post url :headers headers :body payload :ssl-p t)))

(defun create-github-issue (owner repo title body access-token)
  (let* ((url (format nil "https://api.github.com/repos/~A/~A/issues" owner repo))
         (payload (encode-json `(:title ,title :body ,body)))
         (headers (list (cons "Content-Type" "application/json") (cons "Authorization" (format nil "token ~A" access-token))) ))
    (dex:post url :headers headers :body payload :ssl-p t)))

(defun close-github-issue (owner repo issue-number access-token)
  (let* ((url (format nil "https://api.github.com/repos/~A/~A/issues/~A" owner repo issue-number))
         (payload (encode-json `(:state "closed")))
         (headers (list (cons "Content-Type" "application/json") (cons "Authorization" (format nil "token ~A" access-token))) ))
    (dex:patch url :headers headers :body payload :ssl-p t)))

(defun reopen-github-issue (owner repo issue-number access-token)
  (let* ((url (format nil "https://api.github.com/repos/~A/~A/issues/~A" owner repo issue-number))
         (payload (encode-json `(:state "open")))
         (headers (list (cons "Content-Type" "application/json") (cons "Authorization" (format nil "token ~A" access-token))) ))
    (dex:patch url :headers headers :body payload :ssl-p t)))