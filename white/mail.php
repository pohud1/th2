<?php 

    if (count($_POST) > 0) {
        header('location: confirm.html');
    } else {
        header('location: index.html');
    }