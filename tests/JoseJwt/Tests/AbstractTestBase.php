<?php

namespace JoseJwt\Tests;

use JoseJwt\Configuration;
use JoseJwt\Factory;

abstract class AbstractTestBase extends \PHPUnit_Framework_TestCase
{
    /** @var Configuration */
    protected $configuration;

    protected $payload = [
        'sub' => 'mr.x@contoso.com',
        'exp' => 1300819380,
    ];

    protected $extraHeader = [
        'foo' => 'bar',
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
        'PS256' => 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.VEZXotB_1rps-xm0lRv4t1NGEN3jwDmuGFCRUruJPZzYXDCXOA4hIHOeLaPTCrYdt_xZBkDo71rVVDcuZCXVAGXYXLsSz4DB6BWIwPGNVRNO_6_9G1Su33yiPi-0gRi07UGEzlvY0SukJP9gORO3kcgVBFjtlmz4kMmPmOlCoq5GRzKCG5JIf6Mg2U7Nt25ts9fBSBZzTA4LfRTqYy19wqpNma-j3ib7gRHlC9G1yla7ePjUPAXswfykcN21F8m_5JTSwgXUSOtFFAg5lDWD1zlhG1lzR_0ySpOhUZXQTu8KD_jso5BskAoQX8lpecx-3PsHaUat_-499wqadJDxyA',
        'PS384' => 'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.c8HmyF_nao7R8YYI1BtUtBdS5q96LqTYuo_xy_BtMypZbdtZOBzsN7ihYQC9VLsLv2SV61_yhV65_CjDziFJtCsoR3ZZ80Qh6fu6MSnb8ep6OtONNp9QBiD4dQLcmACzluCUC4QcIpJ3a9GDogpLoVCcKN4d7hdHFRFyf3TuTj4W5DjizxnYX8FMDDxVam6EqX85E00WkB4GAJ_QC3vJy26yNirmAC1gLldaeiTlEm4JaucDJWhxcdAzBhmC9IsYwXkgD3M8YfjTxXJbBdQsyFddKbiZQrfo231ilOuz9vHe7AOPinTGdTAvJryA1JD7-G_4lgEyYq6iIijCeCqu4A',
        'PS512' => 'eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.iIF5eBl1tFvEJd7YvQZQpgS-MygGWwMhSI24yMZDvvJkRrEquvuqCbLpjS3dlCUUfZB3jIXHhaFkFLQueh9S3_9U8akHZ3sKC2hPklC9dGS0oDnQmHG5DWyQ4JdrstYHE_rLrqcwMW2usB8jSoGw6lPvnba5dlkht3tqkfaeSJ3-AH6jgTQPKQ7xZ1lPZvujBsN-ZIUoG5mGt5UZy7qdn01tftX2vhnxwnlK-dy0E6nPNVQyJrO-8vng9VT2mp-10EpdUPA6J1dqavSfNUfr9lQOdeJATiWm_2bbG4AIJ_ojYUtt7zT-_Va1jR5WbmXetR7Zy4jq9f-2wqQiG0Mr3A',
        'ES256' => 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ._TvpAUJH8WY47XyecG6R6p6qYhyzXLy9QPVLrr0FerhodBw5wc3b-fVkR1roy8xYnVEcNYRCXj_NcDWwIv2nsA',

        // JWE
        'DIR - A128CBC-HS256' => 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0..GQ6zS4dZQyTEOm0WoBMO-Q.1EAzHR6g5qaFOqfi9QfwFevrZ1Y_T-0f9XPlIXhyHbtik9ROz5nTleDd01rjuSg1.jwpfH3e4Wj1-STH5F3LR4A',
        'DIR - A192CBC-HS384' => 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0..sAjpAaZ67Nw3LXZJrbsWKg.lqcrrmyQBTZhOxyZGC4S4hcKjn5WcBAepDl3886xiNKa7MRzkSZfG5_tlcn23i50.TlWmtxWw7_X9q-7N8z8WBKLTiEySRvql',
        'DIR - A256CBC-HS512' => 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0..yyIDhnF0RjVJrOThAP0bRw.G6yg0g4klI55dQfFMASEGiDRaM93dzOrzoVaV2vJQkRtAK-7hCp53q7KJxlcEkBQ.oDKDpLkeLplxpLdmW0S1UgP0UqfeQKl_iBZpEDzOM7c',
        'A128KW - A128CBC-HS256' => 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.PJ64h2QReKlVJKSSibBSoOTjU4BLY9dX732cxQamWjTNejj9uHWtfQ.eUhSFRVJXa1cnqdmxW7pHA.9wJkZNGqWXKUzQFnhVNWeFke6mW4lCSUmE_qhdm9yr7--eCzZr5boXcJUACiRX38.6x21DWmvjPJLrdWkJMe_dg',
        'A128KW - A128CBC-HS384' => 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.Bv6EIiofuZ4f2eQIQDaBbse2EqafFkpF1bx4ZfaEKhTYhgsqtPJsZB5OnD5y91wmAq3gq3O8c4I.j9EorUM0V8FDqy7HHI3JBA.wrvKV0cgS8hrJ_XVZMwyM6Uh-SqrpcOYsSoMcoXS-ZU4d1AwzhSJzt8YIV2GTtLj.8Ql67B5-x3DjqrSG5SeLT1f53r_woxwt',
        'A128KW - A256CBC-HS512' => 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.igcnJanPs-Ye_uOQdGNbZlqMbBCuob7sD3OdhT-uj0nV5Ji74HL9myhTSgvFj7llcHccMSsL0RorgxIGgWXWU6rGfrrOwIeX.DFa0q3yFVNoD-tJKJvqCTw.V3M7NuzIcuF_fcDkKsozgzj6878kxZLEeY0MYlPRMnIik00smZzwDRchaeG-zPzn.TQCCs95Wudmiey-peZ2FgWXVe-DUF409JTWrD6tXBJk',
        'A192KW - A128CBC-HS256' => 'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.Y95sn4FrnKhnrtkvrtNRECUXevXHyi_2pIT0gLUSbFUPdPvIORzRNg.dhj5wXOvOhtY5GF9Q7jn2A.2eSrjxCvwTn_K9iRSfWHXAmGClM3_5rLzbmPs0ha8bnC2ED0ncyPWoTYkyLVk46B.YqVw6OT9YLascX2CH71qAA',
        'A192KW - A128CBC-HS384' => 'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.iyK39_FsV8Jd1XpvL_vvZ2_bXZ9AynxIGUZ4Zyu1L99LBxYdOEaok_hWU1hARt31Xz4SD6tXCVU.WsUQ0Iax8TQ2fU7P6asVfA.b6rQRM4tJGOVfJLsAT47Hc2zPl81qV1FQbDpwt5ItRMrXJSVDGitWrDbk0RetbtJ.cDubLTdH-0mKBMgG4POavewlZBsnCtsE',
        'A192KW - A256CBC-HS512' => 'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.jtB691Dbet2wvr8vAC2THZIirKCmP1HcC0HQWLOIHERjhnJZvJO8RQAsksCMymdoeu83IHOFO2Tci_CaueXxxv7SKcpKYSNL.csCMXumLBkcKF8OmFcBuMA.9bATlTpkYIKRHC3Odwtx3xKZLfTSagboiVmegZnkcYtM3h4eaXk_ehcl5vEZ097s.cGJkDAErDv4QHLYSeXlOFgJcyo919LjvS4lufnoJ71Y',
        'A256KW - A128CBC-HS256' => 'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.6BvA8kXd-G54GyKBhipRLd1gCyFNDml52gjJEwWK_VrzB41_6ldhWw.2ShlqjT8xMYJhJ4AlMqi-A.WFgqlX29_0rWlTw3BI9eugjKymAEV5-e6ti0HeBh6WjqP_B_6L5xbE2fT22AilRK.dr0qvKiHhrADjvm8oob04Q',
        'A256KW - A128CBC-HS384' => 'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.tudD9mkge0Z7ZTV3PMT0SN5d85TaQX565b5PgB_on45U3bcZTWXB2aUEEUzHaAmOlXs-PuLRqRw.qL5FgooeOdSSCTgpVgscEQ.FndA_UpAnYC353UngQVSE_RQ0Ni95LBkGjF0i7tZl1lXrLVRAVFxnIIKlHjOJRUN.fdaRVcY1DLGhbkusiZcYfzPXusQHPTDe',
        'A256KW - A256CBC-HS512' => 'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.HFMUcoGhqqwuXfupBwjcQy-mtLgEuEvZOhoqShB7TsYBn4SVIijnXc6jSOmhSsT_t5E2gL6a4rry8zBT1b9cVbK5loOdjZE8.RBfWq_BqvRIL6dCz-GXQbw.JjcB2CX1nM9o30t1iLicdpGsNArQ4ijgqgXSBjz8v8qco-NTz-pbM8IgGb2xhLyl.AOnFWYpMNnSy4ED4Ir7caje4iSqtIiL9TSaGdYhF66g',
        'RSA_OAEP - A128CBC-HS256' => 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJ0eXAiOiJKV1QiLCJmb28iOiJiYXIifQ.XwTaSovl4NqdK4j9gTkGPoj3tre46aD0bE6SeDkQFmaAV63gWbCtJ8ZqfynCsFjKBGpjRBLugEQY0dlDkDKvqfYA-KkUvdiAY5tdQjY4a_4-45bBf8yuM47dZAxxYBS83H7w986RovRsWmKQZtOFEJyfMocpxkhRAV5rCCXZZPlCgTkBufoyDEaiHQyHzuEOfH8XLdlRjFu-gqaCW-Iu56wTBIna2MCJ3QNL5ViD8lwcaMh8GukLBfB98hkp6qU40OgrGRwXsQdCaXNJgJNDY2ezxh1_spWxqHhg4jbs137NUUYYFfpB88qa3wIA7Qm1k-tvT20iFISOi9L9oJGWCA.Ihv5AI5ISgJQelyjttma5g.86WVuFf6KPGVSTMtsFlsQ7KoSzeuDs5G4AnJIP3-ZEa2q8t1hHrQE0JStdEA75be.X2zN6yuS8awO5kc9SFe__w',
        'RSA_OAEP - A256CBC-HS512' => 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJ0eXAiOiJKV1QiLCJmb28iOiJiYXIifQ.a9Zv8IMhN2Zr_iQZxCRz7NBsMmPZ-5SE0K-Z4igGpJZjz17Ol0d_ITtGVAKUoe_hk4HwSz6I5ysY45zkyMScCRvmg3IUexDRTMpgAD472e1E_X16sb28dHLlxYdnMTIrXdOukictUGcQxwlxVEyH9UtECW6ey3J1ZH7d13AgSQB3mQOo_LlRj--GyIBO4rQkR71xfPw-goPjVn1J2-PTMSSyxoJqJIXZjob42JGm76dfIVrkLwXd0f8W6wxXYPz_jlkWw7XDWWy5WaJ9GEfyXNfFndRaG8FOC2Iszw7e7bfGJoarg1xalfz5EYedbfjildWzTNazNmzT2zscjW-H6Q.qty3aij18dPKMA2fj3JZAg.carxfr_QpGUUdgPZbpugaU4v6BolhjqfN_3dRJXKcVGMZuZiyOdQz1OSBhMs3nig.sDMykx-IxR8sGJ3sDF735bH48kbrA7qxVYp_14baT5o',
        'RSA_OAEP - A128GCM' => 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00iLCJ0eXAiOiJKV1QiLCJmb28iOiJiYXIifQ.KPAFSs_VGnfUfEZ1Hgp8ERIVIvTkSZtmltYPuVgP6m3ryARVAyx8INIEZJsxC9Y38-n9gF7E5SnWzzghey038qcr1GNZPn2aj7HL7aJECPO7fKCX2lEUfu3vgQuwhF5Eq-Mo_tEBBgGo24O9rQeovfXJM2GKxquexYdG6RbkacmnMOA_D9ZyplLAWJDfG6MDAMil7Xyeibq8xLYu24CUmkj9tnOMHMrqztnsY11I8oL3NMU2c97sj-d-gMqIABg3xr8eu3KhDhnyT2V26dcc8rDYDYMkz9qeeVwvDZaa4sxXUv4Jg8BtV9qync1Pwund-crRcWR9z8KlThJkxZDpVA.z9ent3iqF92vsyka.j4Czxkoe2uH3NwVqFX7Vw6yYHPr3iccnYTtho5V1fZBGvoJ_rGQAh-SDww.T9fT5D3KE2flWoSXwstMeA',
        'RSA_OAEP - A256GCM' => 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJKV1QiLCJmb28iOiJiYXIifQ.q5giVHbixIiizd9q37ioJ4Bk27Mhu8g_Qz1-4APUvrn0842SUH0x2N8-EH1YgYz-qJW-8ZD7o84cY5yqRYHKXcglD3Nen_XcmJ3FD8OrA98I7Y7ZOFWxKwopxWQ77sjOhykpJknsrbmaH184TXZ_UChee4EX45MddBECnbr2R4Fyolw5N1TjGA0tKcRxOL7MHADYM5qBMl8cSO1XatTqfGaKqJ6i8d640nO3SoFl-xiF1qbeSvbRtdMdeVvhCpSELY4F8b248LQfliaWG4up0aXARKHgEcXp95u7dCiJTDQCybTIKRws7vIly5QKY23jXKyIYBFCqZ8buSbU6A2rdg.2hmf9zANliBa9sTm.TzzlP7ALG80xWQ3nw5NtGX3ty78Kp4FjJVjDQWhDbDJHjM4W8o2o_qOFxQ.5boHfEh9WpoQvBxaXGS0cQ',
        'RSA1_5 - A128CBC-HS256' => 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.ZyWP_xYHSEdUafb927PEda9DB9Zx5qqR5IQU-tf40uCtBRIHnghgUARzRkLSrGSOfQ63eoht_vlxyDhtcdrykJ9EhzkK2Vy7IcZeM-tTaxePApeDA67PpJo-Z0FdSGOwYLgE7yVsLUe44hSMwUoWRJEnBMA5xZbw2YKedZW-Pd1xgwl-uBgZCl24McZE0NpbFqT_RP23ZKLNe9trqmG5su4bJz9iaf9K6cUgAsls1q7PwL6OJE-2cEMkRtT1jKOih_9_-uK32he4mJyQasRUyq7muPM1kueuucd7j9aFMl7al59rPVofFdozn8lyYUyLpssms3GUUQIy4OHBHXCpGg.ZOFG5da6bIrTol5owujZ5g.FU4i6j6OnpsTrKOaT8_eOHscZtQLUDWpfHKjwVHBaWAc_7q58hSw-Xwg3YA793zG.-eypre_7XOVq1tY23OTGmg',
        'RSA1_5 - A256CBC-HS512' => 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.H9zwa3IAdcDsBWlAbXhhBmWoRLaWulYFjvVjuYFDUdvYF_v9zNC-pJqbja-RzAtHy3cE0BJnyUFrRaAVAchCHcGxdZij2znvlugNxihzGmy70yOSH7-Qwmex5Wb_v846UHM4AT2MJUcx44m-R_3JB-5J1gAwh1tiUXlIUwY0J5IeLenrMEB5e0W0q48GbLPgzuc3frft4IiAU-3XqknwuKabfJpSHWzsUV1RMCCnVSbZ7WVyn2Zq2ZMnsV2Xyb60hYdVn6zo3iqKYtzmXmbpwu_BmlzoDlA36X-VpGWRytJhitbXczyF7LWAEhJnbc49oq2lD3JdazGSrU28bgZVkw.sUfGew8cvtfPyo46h8OvRQ.mHyTh94CtYaJNPoM6EaaBChuJ6AFmdmQQLhBp_waD8AUaKft95cJ3qGYeeZH5aVN.7EP2dvNbUJi1nM29XR8TQ6-WjxJdW1J0FVw38ABFa6U',
        'RSA1_5 - A128GCM' => 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.vL2-4hdVNZ8OsxlVwG1Lq9LMwwMU9tBUkOMwIbM5OC7tRrRC3TCndBNcJtWKQ9yTLSGMvNAk8sKC-EKgh2nvvoGI1XiEtLfXqJ5yIbaG4zESHkWXwj4fefEigCdo_Xd1bDaFOWuqJ0aKDimqCgmYVVcEpcQk5fdgO_J8Zp2ZJPtOVY-OptRf1QRX3oQosV01xOzyLS0UZot6ofG42-YxYI4pFvi-AJoyV5VeImdpCBtcwvnHgYp9G4kAy10ajs9kKigGQ6z1CZEJONwF7uXjTIWeciazWoMBJFlKIH8n8n7zMsC517einuVmgmj_Wiii3FQEvlriTPj_fU74DaOgtA.fqQZ35Jkj1rRVK_G.lfqln5nhrKfpBLCUZkvRACSUDNVja-oAfzdajobB1jl0bccZIJakiDoBTw.DRKlM5L44jZgZaqEMvBl0g',
        'RSA1_5 - A256GCM' => 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.AGJPvYs8qN4jw10aWhHpBewlcStB0j2aAL_e_0O7oy1FiPuRXN1rhB5CMhwJNznxLpMC88PwGXKvbXo6EaBcRVh_jiHq_dtReRaWlZkwFbrtF8O_XapKnoJszCkoWL1bpatiXkVIYBlTS2LvD5P6z0EWI0-EN40BfXd99Wg2SZ7XqOJzKSBpwJgZfGOp8UEXAS7FvEV3eNisaQxJaLn1RLfAgnO3VWmD52htNK67OeUMtgJ7LpmEV8bfRMcX6uNOgRw8Qopt_jRmzXQxfkLxmmpsySI23NoHU41vgphFnU8QO7ESU-fDw6Sq8iu1gR18Wvrvj_2dNxhfkO0Sy0okIg.R-labo3zVwa7e1fu.JZViHKIgf4XO6R60mhqko4o4nxkYrOWQgLRo8Y3HQkbjHEj2RLg_ehqxiA.2y1cZpQoFe-pZ8HGAdsWQw',
    ];

    protected function setUp()
    {
        parent::setUp();

        $factory = new Factory();
        $this->configuration = $factory->getConfiguration();
    }

    /**
     * @param int $size
     *
     * @return string
     */
    protected function getSecret($size = 256)
    {
        $len = $size/8;

        return pack("C{$len}", 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234);
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
