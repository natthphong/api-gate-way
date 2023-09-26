package th.co.bay.ksas.bondprofile.service;


import com.amazonaws.services.sqs.AmazonSQSClient;
import com.amazonaws.services.sqs.model.Message;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import th.co.bay.ksas.bondprofile.adaptor.PassBookAdaptor;

import th.co.bay.ksas.helper.util.JsonHelper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@Slf4j
@RunWith(MockitoJUnitRunner.class)
public class PassBookServiceTest {

    @InjectMocks
    private PassBookService passBookService;

    @Mock
    private AmazonSQSClient AmazonSQSClient;
    @Mock
    private PassBookAdaptor passBookAdaptor;
    @Mock
    private ResponseEntity<String> response;
    @Mock
    private Message message;

    private String req;

    @Before
    public void setUp(){
        req = """
                {
                }
                """;
        when(passBookAdaptor.createTxn(any())).thenReturn(response);
        when(response.getStatusCode()).thenReturn(HttpStatus.OK);
    }

    @Test
    public void whenSuccess() {

        this.passBookService.createPassBookTxn("",message,req);
        Assert.assertTrue(true);
    }




}

