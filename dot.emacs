; --- load path ---
(require 'google)

; --- basic setting ---

; Enable font-lock
(when(fboundp 'global-font-lock-mode)(global-font-lock-mode t))
(setq font-lock-maximum-decoration t)

; Enable windmove
(require 'windmove)
(windmove-default-keybindings)

; Scroll one by one
(setq scroll-conservatively 1)

; Find file from home directory
(cd "~/")

; Use bash
(setq explicit-shell-file-name "/bin/bash") 
(setq shell-file-name "/bin/bash")
(setq shell-command-switch "-c")

; --- key-bind ---

(global-set-key "\M-5" 'replace-string)
(global-set-key "\M-g" 'goto-line)
;(global-set-key "\C-[" 'previous-buffer)
;(global-set-key "\C-]" 'next-buffer)
(global-set-key "\C-x;" 'comment-region)
(global-set-key "\C-x:" 'uncomment-region)
(global-set-key "\C-h" 'delete-backward-char)
(global-set-key [(control ?j)] 'goto-line)
(global-unset-key [insert])
(global-set-key [home] 'beginning-of-buffer)
(global-set-key [end] 'end-of-buffer)
(global-set-key [(control ?l)] '(lambda () (interactive) (recenter)))
(add-hook 'c++-mode-hook
          (function (lambda () (local-set-key "\C-x\C-o" 'ff-get-other-file))))
(add-hook 'c-mode-hook
          (function (lambda () (local-set-key "\C-x\C-o" 'ff-get-other-file))))

; --- mode setting ---

; Move to line head with # in C mode
(setq c-electric-pound-behavior '(alignleft))

; Javascript indent
(setq js-indent-level 2)

; Web mode indent
(defun web-mode-indent (num)
  (interactive "nIndent: ")
  (setq web-mode-markup-indent-offset num)
  (setq web-mode-css-indent-offset num)
  (setq web-mode-style-padding num)
  (setq web-mode-code-indent-offset num)
  (setq web-mode-script-padding num)
  (setq web-mode-block-padding num)
  )
(web-mode-indent 0)
  
; Solidity
(add-to-list 'load-path "~/.emacs.d/el-get/el-get")
(unless (require 'el-get nil 'noerror)
  (with-current-buffer
      (url-retrieve-synchronously
       "https://raw.githubusercontent.com/dimitri/el-get/master/el-get-install.el")
    (goto-char (point-max))
    (eval-print-last-sexp)))

(add-to-list 'el-get-recipe-path "~/.emacs.d/el-get-user/recipes")
(el-get 'sync)
(el-get-install 'solidity-mode)
(require 'solidity-mode)

; --- view ---

; Color
(set-face-foreground 'default "white")
(set-face-background 'default "black")

; Don't show tool bar
(tool-bar-mode -1)

; Don't show menu bar
(menu-bar-mode -1)

; Don't show startup messages
(setq inhibit-startup-message t)

; Don't show the first ox image
(setq initial-scratch-message nil)

; Highlight words when searching or replacing
(setq search-highlight t)
(setq query-replace-highlight t)

; Don't blink a cursor
(blink-cursor-mode nil)

; Color of selected region
(transient-mark-mode t)
(if window-system (set-face-background 'region "gray70") (set-face-background 'region "pink"))
(if window-system (set-face-foreground 'region "black") (set-face-foreground 'region "black"))

; Brighten corresponding parentheses
(show-paren-mode t)

; Ignore parentheses in comments
(setq parse-sexp-ignore-comments t)

; Don't use tabs for indent
(setq-default indent-tabs-mode nil)

; Mode line color
(set-face-background 'mode-line "pink")
(set-face-foreground 'mode-line "black")
(set-face-foreground 'minibuffer-prompt "white")
(set-face-bold-p 'mode-line t)

; Show lines and columns
(line-number-mode t)
(column-number-mode t)


