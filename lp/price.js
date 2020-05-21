$(function() {
    country = $.url(location.href).param('country');

    if (country == 'TH') {
        th_selected = 'selected="selected"';
    } else {
        th_selected = '';
    }


    selects = $("select[name='country']");
    selects.append('<option value="TH" ' + th_selected + '>Thailand</option>');

    var change = 0,
        updatePrices = function(item) {
            change = 1;

            $(item.children).each(function() {
                if (this.selected) sel = $(this).val();
            });

            if (typeof sel === 'undefined') {
                sel = 'TH';
            }

            if (sel == 'TH') {
                $('.old_price_val').html('1980');
                $('.old_price_cur').html('฿');
                $('.new_price_val').html('990');
                $('.new_price_cur').html('฿');
                $('select').val('TH').trigger('change');
                initializeMask({ mask: "(+66)99999999[99]", removeMaskOnSubmit: false })
            }

            change = 0;
        };
    $("select").change(function() {
        if (change == 0) updatePrices(this);
    }).change();

    function initializeMask(mask) {
        $('[name=phone]').inputmask(mask);
    }
});

