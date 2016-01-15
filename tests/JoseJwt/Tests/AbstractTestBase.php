<?php

namespace JoseJwt\Tests;

use JoseJwt\Context\Context;
use JoseJwt\Context\DefaultContextFactory;
use JoseJwt\Random\FallbackRandomGenerator;
use JoseJwt\Random\OpenSslRandomGenerator;
use JoseJwt\Tests\Helper\RandomGeneratorMock;

abstract class AbstractTestBase extends \PHPUnit_Framework_TestCase
{
    /** @var Context */
    protected $context;

    /** @var FallbackRandomGenerator */
    private $randomGenerator;

    protected $payload = [
        'sub' => 'mr.x@contoso.com',
        'exp' => 1300819380,
    ];

    protected $extraHeader = [
        'foo' => 'bar',
    ];

    protected $randoms = [
        'DIR - A128CBC-HS256' => [
            [46, 176, 178, 122, 18, 112, 28, 188, 208, 185, 82, 24, 109, 234, 145, 77],
        ],
        'DIR - A192CBC-HS384' => [
            [142, 0, 62, 173, 193, 132, 227, 33, 56, 183, 7, 132, 247, 211, 74, 42],
        ],
        'DIR - A256CBC-HS512' => [
            [202, 81, 84, 182, 58, 156, 220, 225, 190, 117, 119, 55, 59, 218, 169, 218],
        ],

        'A128KW - A128CBC-HS256' => [
            [205, 192, 241, 136, 209, 105, 90, 73, 100, 193, 57, 77, 64, 119, 114, 6, 185, 49, 191, 211, 101, 181, 187, 83, 99, 119, 193, 94, 255, 245, 203, 68],
            [215, 117, 52, 228, 0, 106, 188, 153, 245, 227, 74, 209, 155, 69, 148, 172],
        ],
        'A128KW - A128CBC-HS384' => [
            [76, 124, 118, 255, 135, 127, 126, 110, 194, 171, 63, 5, 111, 54, 81, 49, 157, 31, 148, 45, 43, 70, 150, 119, 17, 68, 80, 20, 244, 148, 204, 76, 143, 56, 152, 193, 205, 144, 198, 16, 157, 202, 98, 122, 81, 192, 241, 222],
            [95, 196, 46, 131, 241, 170, 133, 14, 169, 223, 83, 171, 124, 70, 90, 166],
        ],
        'A128KW - A256CBC-HS512' => [
            [61, 189, 183, 40, 191, 72, 89, 71, 250, 178, 119, 94, 49, 249, 190, 39, 178, 219, 146, 65, 8, 224, 50, 121, 118, 232, 74, 199, 60, 116, 25, 172, 184, 58, 185, 226, 213, 190, 113, 230, 143, 109, 211, 93, 164, 4, 221, 178, 36, 70, 4, 67, 184, 1, 145, 29, 255, 189, 5, 89, 172, 112, 53, 205],
            [70, 52, 73, 124, 119, 231, 142, 7, 88, 203, 217, 131, 197, 183, 24, 239],
        ],

        'A192KW - A128CBC-HS256' => [
            [197, 232, 248, 234, 188, 108, 145, 143, 58, 53, 33, 80, 16, 29, 208, 77, 98, 42, 32, 74, 228, 52, 89, 39, 222, 248, 30, 1, 73, 26, 186, 4],
            [168, 132, 221, 173, 227, 109, 244, 68, 38, 44, 24, 138, 247, 84, 17, 81],
        ],
        'A192KW - A128CBC-HS384' => [
            [33, 43, 206, 226, 63, 180, 97, 185, 253, 172, 49, 23, 106, 167, 205, 20, 211, 166, 115, 67, 35, 66, 95, 237, 5, 58, 128, 140, 235, 5, 30, 89, 148, 192, 106, 150, 40, 141, 239, 86, 153, 74, 79, 106, 212, 110, 148, 172],
            [130, 132, 81, 208, 195, 160, 155, 215, 227, 48, 226, 96, 94, 60, 161, 103],
        ],
        'A192KW - A256CBC-HS512' => [
            [231, 184, 103, 254, 21, 29, 218, 135, 6, 72, 82, 61, 26, 57, 129, 118, 166, 184, 13, 44, 227, 242, 254, 248, 161, 82, 166, 54, 158, 64, 214, 2, 149, 206, 182, 232, 250, 75, 102, 234, 36, 89, 243, 134, 80, 111, 94, 134, 82, 26, 164, 94, 40, 99, 99, 236, 203, 141, 137, 159, 130, 190, 217, 253],
            [157, 69, 161, 126, 225, 38, 168, 163, 46, 130, 68, 252, 210, 243, 52, 186],
        ],

        'A256KW - A128CBC-HS256' => [
            [84, 0, 185, 118, 84, 83, 121, 24, 150, 94, 238, 124, 103, 61, 205, 70, 0, 129, 240, 209, 85, 160, 72, 186, 148, 178, 217, 37, 160, 207, 248, 32],
            [132, 5, 150, 107, 215, 251, 225, 23, 63, 159, 35, 118, 115, 14, 175, 129],
        ],
        'A256KW - A128CBC-HS384' => [
            [143, 98, 145, 162, 67, 108, 146, 97, 54, 138, 33, 10, 162, 28, 241, 103, 205, 35, 241, 147, 254, 23, 252, 92, 66, 193, 144, 172, 90, 50, 201, 186, 230, 244, 72, 208, 70, 3, 153, 145, 87, 59, 47, 169, 33, 32, 119, 65],
            [11, 134, 248, 96, 188, 71, 64, 188, 128, 8, 119, 174, 240, 215, 114, 188],
        ],
        'A256KW - A256CBC-HS512' => [
            [175, 109, 98, 192, 125, 29, 68, 137, 44, 128, 182, 212, 18, 34, 72, 2, 113, 229, 182, 202, 139, 219, 135, 148, 182, 175, 203, 27, 65, 197, 16, 62, 127, 219, 236, 152, 6, 75, 219, 253, 134, 170, 191, 121, 30, 250, 200, 205, 125, 21, 117, 177, 70, 250, 38, 240, 149, 202, 122, 63, 149, 213, 66, 145],
            [149, 73, 120, 87, 156, 246, 156, 71, 227, 110, 168, 77, 161, 68, 17, 205],
        ],
    ];

    protected $tokens = [
        'NONE' => 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.',

        // JWT
        'HS256' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.j-zS0EuiwCsVlFUKzAaNYsYkETom9bBtEqmkSiKDqrg',
        'HS384' => 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.f6eGKPC3fCS6lRQ3O7eHbRhv4D9cSJ5tGZS9vbcPIKrYDIzic0hBLH9__seOqZkY',
        'HS512' => 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.j2pU3ic1aQubmxG8MuekAObFOFRmeKJ0uBhaU8dJQR5jIq55fPj83keqQ6b4BpsAlG5OhwPk4aUqcs7vOtZ4Aw',
        'RS256' => 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.XW7oSrjnyF57T4jUz0HEVrCG-sKddIZPvBZriK7p6ZMYy_KUyahzYhnr9UXQUMFBQw59kvTmay0nUJwAhuF3zRBmV-1yT2J_gH8BUeVwGTm2AWo4d-Sbkrds9_oQMg6OWucWTcoL3j4FmS8Q0pxXZae-dkA4ZfJN3vitGcsKX9OzlkgyJ6uFR1tKZA4bmkxS8kDyw7H28EAtl2B5PUCS-xPxivvXGIN6ZtTwpWwzF4AJ1fHmL-Y-wN3LSpMG4WNEnpK3L-GEkPz5yPP7cF1pr-rIKwkokrpJH4JIxur9his4UrinONg8Kdj-lwTPFbM0QySEnikMX76x-ksPFQuZrg',
        'RS384' => 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.BbcpQNheeXFu2Pnp5tfcRYuDW-pu-N-81KLwu7aw7mqsrQPxi0tcMDb7dqiWZ9r-c5YKGyWrK2gVX66c3-XVhOfjhlJCBBf3Tn8I8z_QCNmAcz0jPU0-l3PzRHnJB8j94Hhw1e40JMA5_5LSLA3eyhQIxGAJaYjHI4blT_-KRA6KgTB7d_Pj64YoB7-D8dhNTKSQMRJm_C_BbjZrxjS7dsfQ9KmBqeM6WsGm2fehLuRY6cCGKv83PXxBWTFAeJ8bWLa5Ena_k6cDu8wDKl0IdEKtaCDedwMcdRgcJxjs8Tu36nZClS606tRfy21P11Pa9Pki91e0l8pafpoEnkrM3Q',
        'RS512' => 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.XcuZL-qa0QLEryFlkTk-0JvFY5Pkqzrw-4xtRPk285L4gqxe8jOhTYI4UkueZkfO2xcdzQCBwZu-u7ceoFWCS-gL2G1bglhJARclsJmxdBA7r_Whzq4AUmOpcF0Oz-cA27ZlpbVD2n-qOPC6aNNubj0DguKPCIrFDfmbcJbcdmpVQPbBO8yyRkH08uDLGEy9v2hnabkrxvZOquRueZg1CzuMghTMsGIct8w1ktV7qD5_8ABS8eU4MIUIooIsmzOOCUBZ1tCQ_rOFvbh6GLyxn3t6dDd85g-u5d-zEM8OlqXGkgqKXhxuMcpu9R7IJJLZTvy-P9ezj7uTpd_Lnhe7wQ',
        'PS256' => 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.jt6cirDpDdZb3O5vySIcrPde4-2Fen_1LDU6jQGqrtm_OFHf2HwcJXfNJsU3A2PrDy90HYOsnux7eFpBgFWbIT4nT2PmSyLRK2BUz6S_56gR0nwv5EY9jI-bnUs-FXMy0xet1NA7smB7AZ4hznqFUMzWhGQB2TfFoO8bhh6WugZVAearLqdqN8o-BoqAS1MLg61NYZg45T1n-PYS7XKlt6LjN0NY70SRU53Gxmq4sdBrlXIwWod4tyfy8sbY1y0WqSr9ZZ7iT55mn6TPjVv0vAh-fUqoQPwhjifCnhFEQOZTqq58PyCb2g4hDeeIrCHN-GQe8MgQ0N-fmOlZr7F4VQ',
        'PS384' => 'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.jytlSJfaUOqu0E624NuIrqFQ7kQ1uFShMQ8VqI2os7cSDupRZk3V5ZD5yNTwRcvm1R0oRaUpHmPSAkJ1gHDOx1MiJFWkzHE4iVCg1Ez-G_T1DrKLAaBIWa56hHCFBl3emHdxG7cHD0QQ4XqnxX3duknZfwTejBc3Ytt0WVcikumXCgONv8kgXeO5iGhWY-aGw5T_jBA24h_amPVjcbyqZFoVsvd3RNQEW4Ya2ENDa1-OR3Rz2tNhy8GUkDgDv73cKhulonNdMlrQiSmtbbUsZeaIX6PYTERwyO-G8FEUDo_utqghiS_KM5m_twH6w5uxIHslnl1mDnCTzt8G_lMR_Q',
        'PS512' => 'eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.bqw3J0LybKnhzbyRY8PZqCqWPp9zgMQL5QR81N1MqnckjETATHzRRvHr3_QoqQAleZLvDMTaSjXk-UpLgMN4CWSAar_L1H5WZUj85js189dq2GKlyUmE-J_ZOeFjnyBPEZvweWkjg5xPOIcR0KmVzDDnXUyK6l2tq-xYhl47A7cTVF-Z5E-LMwDuragHaKbL0sL-w5ZPIkvFqwfyCHSSB8MR7fgf5ZA6d9BEzsdTW9Gwbk0AFD6mS_aQJXT1v-MVTbcdMXwLrUqR4QHj2m4FlRH311CJa-piKKI52M6Ftz3ZWu3dno_7hz-azb88qQrAjZGg9xTbhmt5X1pDzN21bQ',
        'ES256' => 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.YmFfGJiFgbK2uZ1RN1P9luXbcVScPJsokBqZgKPcHsq1jy3aiK5KWPE1oQwOkMDtjlD8bYf8zLS9mynqtdVH6g',

        // JWE

        // 46, 176, 178, 122, 18, 112, 28, 188, 208, 185, 82, 24, 109, 234, 145, 77
        'DIR - A128CBC-HS256' => 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0..LrCyehJwHLzQuVIYbeqRTQ.CtaBb71vAiSBvWY-9qKET3bzXMs02_WMpbk8mkmuL0OTy8-G07Ld4TvFGMp-uCpP.0cdUoQLcOK45zIo6x9YTpQ',

        // 142, 0, 62, 173, 193, 132, 227, 33, 56, 183, 7, 132, 247, 211, 74, 42
        'DIR - A192CBC-HS384' => 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0..jgA-rcGE4yE4tweE99NKKg.zi4ZUKlTDY4wjrgZDr2kGR28a1-jw26GlLvoCdADYAoHfHZlZO7f9gzSpXanKwON.7-CPY_3GVik273fgA-lWV37IjaatA3oP',

        // 202, 81, 84, 182, 58, 156, 220, 225, 190, 117, 119, 55, 59, 218, 169, 218
        'DIR - A256CBC-HS512' => 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0..ylFUtjqc3OG-dXc3O9qp2g.9aoN8qpGTxc10W6vmmODPO2zPE6yDbjeTatDZqqKqiKPYtuXNacXfeJpkGd_IjSz.V1b8Sk8zXwE4Ot18gYru0prUBYifBef1HPGNoMGPg1k',

        // 205, 192, 241, 136, 209, 105, 90, 73, 100, 193, 57, 77, 64, 119, 114, 6, 185, 49, 191, 211, 101, 181, 187, 83, 99, 119, 193, 94, 255, 245, 203, 68
        // 215, 117, 52, 228, 0, 106, 188, 153, 245, 227, 74, 209, 155, 69, 148, 172
        'A128KW - A128CBC-HS256' => 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.XfLEB5svez-i6UhBrcmVh1OZq97od3BCI-SMA5VjhxxAKVx0625Kxw.13U05ABqvJn140rRm0WUrA.lMJUGGBEgoGdvOyvJmm5ZXuzGPkpmzbdrQkzCz-drH9dYpU7iEFT2ts1kaj0EorD.ZzClMozXMmmp6XM2q4wwlQ',

        // 76, 124, 118, 255, 135, 127, 126, 110, 194, 171, 63, 5, 111, 54, 81, 49, 157, 31, 148, 45, 43, 70, 150, 119, 17, 68, 80, 20, 244, 148, 204, 76, 143, 56, 152, 193, 205, 144, 198, 16, 157, 202, 98, 122, 81, 192, 241, 222
        // 95, 196, 46, 131, 241, 170, 133, 14, 169, 223, 83, 171, 124, 70, 90, 166
        'A128KW - A128CBC-HS384' => 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.9_96GrOgZ9OmHIrnqYGD7EqG3tVT-8L59OrlE19pgbymbsUcI8wXd156TVAkV7Vdv3YsB0a709I.X8Qug_GqhQ6p31OrfEZapg.bdLgHK5JqSIJCzS73_70w1vd7Me0Lx8QsTI4JVJA55izUYqO4eOpt9fhpkL1Pofv.u-Rgnr-rct3_Rw2EszCADc1PMPaoleV_',

        // 61, 189, 183, 40, 191, 72, 89, 71, 250, 178, 119, 94, 49, 249, 190, 39, 178, 219, 146, 65, 8, 224, 50, 121, 118, 232, 74, 199, 60, 116, 25, 172, 184, 58, 185, 226, 213, 190, 113, 230, 143, 109, 211, 93, 164, 4, 221, 178, 36, 70, 4, 67, 184, 1, 145, 29, 255, 189, 5, 89, 172, 112, 53, 205
        // 70, 52, 73, 124, 119, 231, 142, 7, 88, 203, 217, 131, 197, 183, 24, 239
        'A128KW - A256CBC-HS512' => 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.mxVQ4b08I27W8piymLN9fH4q4a2ywCWVoQx2lMZtgUuHduEcUiNWlhsNGlOLthSYhYZlyqeIZvSkIw51oK2u4Mlt5C1LJoM2.RjRJfHfnjgdYy9mDxbcY7w.akKubZH4cXWSb69U8Fnsew5DCEuzNCC5YOb1bPvcCzjXrpMHcQdSIh0aC7LKMbEC.ccnSdXY39FMbLVY--vt3E73Uaz5-4eV4O4TJV6-8lbA',

        // 197, 232, 248, 234, 188, 108, 145, 143, 58, 53, 33, 80, 16, 29, 208, 77, 98, 42, 32, 74, 228, 52, 89, 39, 222, 248, 30, 1, 73, 26, 186, 4
        // 168, 132, 221, 173, 227, 109, 244, 68, 38, 44, 24, 138, 247, 84, 17, 81
        'A192KW - A128CBC-HS256' => 'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.0DA4Cs117rnOJ34BUlNaJioHTl1ElbeZYelVOp9yVivSNEfMT6A4RQ.qITdreNt9EQmLBiK91QRUQ.fySAG5HxhYAcaup2SP_bMied2I78IzHZlAOIrFGvhKXIQ_2h3ikcnmHcYJP4TVrH.Ck6Z0G8unaGQ02Sy_EBUsw',

        // 33, 43, 206, 226, 63, 180, 97, 185, 253, 172, 49, 23, 106, 167, 205, 20, 211, 166, 115, 67, 35, 66, 95, 237, 5, 58, 128, 140, 235, 5, 30, 89, 148, 192, 106, 150, 40, 141, 239, 86, 153, 74, 79, 106, 212, 110, 148, 172
        // 130, 132, 81, 208, 195, 160, 155, 215, 227, 48, 226, 96, 94, 60, 161, 103
        'A192KW - A128CBC-HS384' => 'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.FgMXdH_GTki0A4ncON4_OQZ4lWsnod8dipFfphXde72ITBGtQPwygmwNIFaaM9o3LSF8J_GC8wA.goRR0MOgm9fjMOJgXjyhZw.iLivz7kJi3XinHcRshbTgcfcP_OCg8L1k3JVNlZaOHY07Q22H-ySO4Z4mKZmq7iM.p71uvat9XyNf0gRZ9vjuXwWbxtddBxUr',

        // 231, 184, 103, 254, 21, 29, 218, 135, 6, 72, 82, 61, 26, 57, 129, 118, 166, 184, 13, 44, 227, 242, 254, 248, 161, 82, 166, 54, 158, 64, 214, 2, 149, 206, 182, 232, 250, 75, 102, 234, 36, 89, 243, 134, 80, 111, 94, 134, 82, 26, 164, 94, 40, 99, 99, 236, 203, 141, 137, 159, 130, 190, 217, 253
        // 157, 69, 161, 126, 225, 38, 168, 163, 46, 130, 68, 252, 210, 243, 52, 186
        'A192KW - A256CBC-HS512' => 'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.dTLcho8ArdvOaH--8UWGSzqaXOALZcZWGU1KomE_IpjGIRa_fhGtcTHgxqZH747zqRuaulBcoPrN5AZfsjKMCaDv2mbLjQjZ.nUWhfuEmqKMugkT80vM0ug.UFj1DHyuSrgLTfNDIfKNv5UwregHI3-UejMn2_hEsQXZ196vQRazHzNjmFJejyjc.Xd8I2RiD0f-fD5mdmwSxO90BdlB-hXFZ4lxeNt9hZQA',

        // 84, 0, 185, 118, 84, 83, 121, 24, 150, 94, 238, 124, 103, 61, 205, 70, 0, 129, 240, 209, 85, 160, 72, 186, 148, 178, 217, 37, 160, 207, 248, 32
        // 132, 5, 150, 107, 215, 251, 225, 23, 63, 159, 35, 118, 115, 14, 175, 129
        'A256KW - A128CBC-HS256' => 'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.lQXaXBQKJbtxT1YZr9NS7hSrCiedhB59y805qnO4T7NAL3KroLHC-w.hAWWa9f74Rc_nyN2cw6vgQ.h8hLF3Q_s1UKhuN1DCR-7wjYf2IPr3MisXCs65DNtN4LlRmH8dUp50O3xypy5S9v.1UZug8QUJPAX2CTv7T_oOw',

        // 143, 98, 145, 162, 67, 108, 146, 97, 54, 138, 33, 10, 162, 28, 241, 103, 205, 35, 241, 147, 254, 23, 252, 92, 66, 193, 144, 172, 90, 50, 201, 186, 230, 244, 72, 208, 70, 3, 153, 145, 87, 59, 47, 169, 33, 32, 119, 65
        // 11, 134, 248, 96, 188, 71, 64, 188, 128, 8, 119, 174, 240, 215, 114, 188
        'A256KW - A128CBC-HS384' => 'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.RstyDDmOWf_vHXBH6mN3IIUOed8HsgK8FmWDRZ5TQ1_nA58I3nk0qemVIuEZRkKG2MljdcOZvzw.C4b4YLxHQLyACHeu8NdyvA.OAg2m4KZh8kTzUx9mYONLvVRuIxrbqlP9x11V2YB4_RnOEvg7UVWbYfususwLhDV.BR5bfs2wqV7LSIbCqsnNxAvGqsA8sqqX',

        // 175, 109, 98, 192, 125, 29, 68, 137, 44, 128, 182, 212, 18, 34, 72, 2, 113, 229, 182, 202, 139, 219, 135, 148, 182, 175, 203, 27, 65, 197, 16, 62, 127, 219, 236, 152, 6, 75, 219, 253, 134, 170, 191, 121, 30, 250, 200, 205, 125, 21, 117, 177, 70, 250, 38, 240, 149, 202, 122, 63, 149, 213, 66, 145
        // 149, 73, 120, 87, 156, 246, 156, 71, 227, 110, 168, 77, 161, 68, 17, 205
        'A256KW - A256CBC-HS512' => 'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.71cyg4rAYYaAxdnnc8iisX-F_opnnzlqF1j__D4Kbz2kwK4MR2vhyRONLAJKvo0xV0e63ntt64tCwx2Mnr9KnMfOR5gAzmsc.lUl4V5z2nEfjbqhNoUQRzQ.rRw-TYruXxnYaf1l2yH6a_PmbyWl3VFu_wWXPEz5e1cUOHPkH07Cq_jg8_bX79BY.Cfi0Ges2rf5J_wrlvsqm66X54GozMlfR-tCCKhc47Ng',

        'RSA_OAEP - A128CBC-HS256' => 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJ0eXAiOiJKV1QiLCJmb28iOiJiYXIifQ.oatWcxZEEyxccXlQtnUq8_Ur3tHW0AISdpDVVQWEblp161o1KBk-_-ZsAQ3Awpg3OVYxhdebi28Oe9OA_dyrBjxWibJrute6PQ-C84jDRaA4jVez-VG7W_m8p_qeKuUoUJYI2KQhZBMJ_mFboAyK_EeGfmrvzn_1Ss1cm16JV4UuUKcnjHLIhJRhIIi2ROg-Cg6yn_zWgjxsqocKgxxecYop0H1A5JRBFb03hF9kLoSp799Q9aRfdnwBymhJTUQWc6Y1LO8mN6LxKgQn2QDroUzFR0mZKA7ljCZ-xDqk5_Mtxy6Q-6S-8qM_1w7BXFSdeKSEihlER2AzDaK6r-b3aQ.VLxlfzfhsX4Cs0kjraSe6A.f8GI_hCPxjdLkf94oQkWi64Kz05gPaQWfVh6rqiiN0N5OC5lPGAoaBXS1M9xPh8l.qs13khpu4Mkx-IWNVBHF6A',
        'RSA_OAEP - A256CBC-HS512' => 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJ0eXAiOiJKV1QiLCJmb28iOiJiYXIifQ.NW2rLaqd-T3OCGU67zIQqufxYA4an9g7yWJHQh3XdwW50pqQUCthRc6nhxLz73--oIRX_cZA23QYbBUlIU7_K6NInsK_Iderxo3QUIPJZx3pTANd5xyl5v9W34xjsebt90_5KA0UcFa8XMsbv1bpgoXx4tVSMfZriNDgh-ryjF4BbV8u45I8xrey6QX9JrdhFgUmIK-oa5nafIdCp5_j0aHgYOK8mbvW_d6wthGmVZREjIB5-R9ky5hi3tjcpjJjyOFevRVGPaNeVH-LuEzgjPVpdis2ZdHWdcpIjsyW_5JXEU6Krc-qhhDtlO9I7bU89INhUCR2ak5WSlawLBEfQg.iMwG_5A7nEqyckdJMeUD4g.DUlAhN0RrOirX6fuJ3Zw3e3ljQNu6sH8fne8YQbVAjZ7p8Uqj2Nq3voF68CEGCxw.hUCsCBqAjzOQoVmIjIpUrPeT34iLKPmY8rp5bfUzJkY',
        'RSA_OAEP - A128GCM' => 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00iLCJ0eXAiOiJKV1QiLCJmb28iOiJiYXIifQ.aD-7NKg0WseB-U06h3dr3fKpeaJhO7TJnbUUHq0V37GfRZ34i4zulXnqaFFUJ2c4Qkkeaf-zI9RTCFFqMib6u_5ACx3QpJu8mf7clmYDfrxfdJWkJtmucsSp4n0N59vq0cpfAo2wPfW4g7BQdRaigILmrh23Mu9Vzqo5q0xQIXJVqQrROiDXC6OLjsItb8br-DlusBW8ItQvuaq5j9OugRguHCy0Bi3WZze2BI5QcjMieo5aq1LtbnFtwYfGxM-VsSAC_bHQLK1UedG96eVb1Gnh0gJviKzevpWHMO8dn31tR6NAizs98-IqnsH8Z8G3Z1uBmGE0rZxQcRMzhucUnA.I3I3JWn8iCYFyno7.A3x6W3nEAxyZ5qyjohtT_WU9Up3qsgOQugSkWzdtv2wgKq7L6HLIxQWqRQ.JgLDOyma0oD7NNCQrvJQRw',
        'RSA_OAEP - A256GCM' => 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJKV1QiLCJmb28iOiJiYXIifQ.LyjQDgO3353ekg6QBxo3-YHN88Kjzps-0cXx2s0FCg7qe2DUtq9R-JCSZCUoWDv6eozM6nvuzlsSlPAAnf5JhqA3D1ey7mvXaozAmetBnjZE1ZCEpTGm8ZmgRoLhmRf7pJgkn1SnuSOdzTS4Y3IL2ydlmC4SnuCP_A5cSZzZbhnVDAekFClYtC8Pl0t8rmElG_rOLdSYPUuHAv2m5gngP221V8OmfsdZciRXkvErnoEHhguZYJeb4Ltj8AF67biNSMmUPKQiXxWDbFyWrfffWteg3H3K451uE1shoVT9X8P7fU1ntNGyQkts5K2lR2bzZJ8JqZXuimh8yPcgiQZAaQ._TxBsEeaTuM6w3D4.1QKUB1IkRGYoTZ43O-awfy0Y0RxNBQY_i-0QmPQewgucORN8v-_oydG2LA.jHS6Yk6EY2Eb8plnn6-jMg',
        'RSA1_5 - A128CBC-HS256' => 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.Pvc1dQNrfLsJtb3fLS60nubhzjMBBF_M2Khg0gn6tfpunPrrIxQ0iby7IZITXELRtmlt1-BtdGrburqulHngizAfPqGLar3ViSECr9cMOgSXih8fZbcah20uBeLrXdUt_uskUqLs9d24Ein0-9hpeeYXs2kUh52jPwqko1H4z9BpdHkukEdYkRvWdej9ZAaI33Mftjor37ov1QwMNX76kSU0PjvivasCicpu2KgYtnL3AZuNB0zgdqJxcmjP6y7NXDVT_rFMETd_xvcutN9G0eJ_cpMa0K_dp4X_3V78TF5xf9K0g-lpbwUd0FkkRo648_CBHJy3LnyW42KpnzYZ8A.I4YZhOUfsWTrmMLCMcgJCg.DYwKoUExOafxZ5lGBH-klZt6aX43O47h7IUQSuf30C5wDZyVIwQhTo262v_f4HHO.rGciR7UOYH1s7TDFTMtmMA',
        'RSA1_5 - A256CBC-HS512' => 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.ge-q0BFl7VgKbm3p6kxC-YV5oLE49Js4CERWVZXyPAZGM9BITLC2jfm1O83dNZje-Aw8HGlcXoAPMqoEDtnRUAVeSE-Gwr7TdxCi7dbRnnlnsN8Q56jnyQDtzTQ0vNOBKo1GpzFHi1BtFkqrRWbeiXKqKBpspAl9NHrn1cyeK74X6uKrhP_es_ur2Bt0hRx4UL08f6LEUbuMXuOSEz5GmFEmlKWYBVFuhWT9HwM9n0Z3s3JsPtzFQ6DXOqTjKaHsRWVKgG9uJ6SrT2WbraWXM_XK2OUB3td2FCFe9WJy3UGJ0NQ4RHXyL5b97-pR-26FRlJ0bQOKELp0xnovSrEefQ.ae-a0ckq_FFv9s29D-6TUQ.XDcHWorY5bBdj4AUXdGs3PyOgXb3vX3x5uyaCq7S9xIAUcnlxrY3rzxyBfRLBsCP.FuZSAuYLN3eK7iO0iSHZFYFMN1CCmIOtXaK2scbBTro',
        'RSA1_5 - A128GCM' => 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.B19vTkBLsFWviM_GGUin2Te0SqFYW3dabENuHs7zfiOblprzhdK9nILv-bnIezBazWkd0nLBsp1-HNXo9R27Om4nj1lxgaPum1EetP1v2HXEMs5jK7pSFg8q0y_Aew1J8XRaLEXNhVa481sIUxkG4hhDXW15VTKN-1jKimGvEE_-iXK90KXHntVj9W-xSkyqcnsREo3toJyCUfCB-kojNeMK8R39D9GB_909dz6tp7z_pqVBPM4dnDlILT7eA_8ChjEblhXLrevJM9UETibStv2sKapczeV2N-hrlLlqKAmoEJzm0lmlkARzXevQgTtzDb1ZoEhe1fX4Q0k82_-isQ.sQ9pHFjhm_y2WUEk.CG7s9GJSta7tq2q1gPVfc9FmegZLZNcGSmENj_1-X-hNNyugBH06-NRktg.62szd4LgEFKguSsodfD7-A',
        'RSA1_5 - A256GCM' => 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.GWTk0amJ8MruT_3ZEmZ1b8H25XwiQPBVvsIaT43bUxHXGrxkm6ehsTap6z01tYE0sbDBcgeMvtBvoHEWxciQDZpZpZdTUvc0n55JK1wdp2K2pirpRKy-IveINwn9eWkrox0XSPdOMgYLOykTs1Qdglh_NFMjwFTGXTlrdmz-QoDlkjNszILUmzVyjBp7izpEB5BA8HcIllHfreOaZA5i_ssHu5PxUp0SjEOe9UnvnJbIFx0TBHCWE8v235nQZWU5NZKio26wAAzZz66D_nWp6eBGNi2NeKC-YxnWH81esYo9FI-Uj5dksFaCn7WzTZcC0GogUs_u_aDgy7xCzuLb3Q.JQR-5IApncFzVCHt.YqtOKQ4Ub4UjUQ6xOb7LNAgM_99KfFy81Zu-nap9vt83edw-30AR7RVudg.DRo6-bUet_qtvCGRO69zrg',
    ];

    protected function setUp()
    {
        parent::setUp();

        $this->randomGenerator = new FallbackRandomGenerator(null, new OpenSslRandomGenerator());
        $factory = new DefaultContextFactory($this->randomGenerator);
        $this->context = $factory->get();
    }

    /**
     * @param string $value
     * @param bool   $raw
     */
    protected function addRandomSequence($value, $raw = false)
    {
        if (null == $this->randomGenerator->getFirst()) {
            $this->randomGenerator->setFirst(new RandomGeneratorMock());
        }
        /** @var RandomGeneratorMock $mock */
        $mock = $this->randomGenerator->getFirst();
        $mock->add($value, $raw);
    }

    /**
     * @param int $size
     *
     * @return string
     */
    protected function getSecret($size)
    {
        $data = [164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234, 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234];
        $len = $size/8;
        $data = array_slice($data, 0, $len);
        array_unshift($data, 'C*');

        return call_user_func_array('pack', $data);
    }

    /**
     * @return resource
     */
    protected function getRsaPublicKey()
    {
        $crt = openssl_x509_read(file_get_contents(__DIR__.'/../../../resources/a.crt'));
        $publicKey = openssl_get_publickey($crt);

        return $publicKey;
    }

    /**
     * @return resource
     */
    protected function getRsaPrivateKey()
    {
        $key = openssl_get_privatekey(file_get_contents(__DIR__.'/../../../resources/a.key'));
        if (false === $key) {
            throw new \LogicException('Unable to load RSA private key');
        }

        return $key;
    }
}
