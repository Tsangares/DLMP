# Images
Add images to DLMP.
## Restrictions
To avoid the obligations of creating a full system that crops images we are going to restrict the aspect ratio of the uploaded images to 4:3 and 1:1 and then if the image is too large, an auto resize will occur to the maximum resolution.
## Additions
Store the data of the image into a mongodb blob instead of storing in a file system so the images in the future can scale.


# Redirect
Add a field to force a redirect of your DLMP. This would make your DLMP QR code link to any other service you want giving you full control of your micro page.
## Restrictions
We need to allow some system that allows owers to remove the redirect. This might include on the front page a jump to admin page
## Addition
The redirect could possibly lead to malicious content so it might be wise to wrap the url entry with a empty filter so in the future it has to pass regex tests.