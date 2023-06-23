import { useRef, useState } from 'react';
import './App.css';
import { Container, Grid, Stack, Typography, Button, TextField, Divider, Alert } from '@mui/material';
import axios from 'axios';

const backendUrl = 'http://127.0.0.1:8000';

function App() {
  const productHistRef = useRef();
  const addProdRef = useRef();
  const addProdPrivKeyRef = useRef();
  const addTxProdRef = useRef();
  const sellerRef = useRef();
  const recvRef = useRef();

  const [error, setError] = useState('');
  const [history, setHistory] = useState([]);

  const addProduct = async () => {
    const serial = addProdRef.current.value;
    const privKey = addProdPrivKeyRef.current.value;
    if (!serial || !privKey) return;

    try {
      const resp = await axios.post(`${backendUrl}/add_product`, {
        product_serial: serial.trim(),
        private_key: privKey,
      });
      setError('');
    } catch (e) {
      setError(e.response.data);
      console.log(e);
    }
  };

  const addTransaction = async () => {
    const serial = addTxProdRef.current.value;
    const privKey = sellerRef.current.value;
    const recvKey = recvRef.current.value;

    if (!serial || !privKey) return;

    try {
      const resp = await axios.post(`${backendUrl}/new_transaction`, {
        product_serial: serial.trim(),
        from_private_key: privKey,
        to_addr: recvKey,
      });
      setError('');
    } catch (e) {
      setError(e.response.data);
      console.log(e);
    }
  };

  const getHistory = async () => {
    const serial = productHistRef.current.value;
    if (!serial) return;

    try {
      const resp = await axios.get(`${backendUrl}/history/${serial}`);
      setHistory(resp.data);
      setError('');
    } catch (e) {
      setHistory([]);
      setError(e.response.data);
      console.log(e);
    }
  };

  return (
    <Container sx={{ py: 1 }}>
      {error && (
        <Alert severity="error" onClose={() => setError('')}>
          {error}
        </Alert>
      )}
      <Grid container sx={{ p: 5, py: 1 }}>
        <Grid item xs={5.5} sx={{ p: 2, border: '5px solid #00000044', borderRadius: '8px', minHeight: '500px' }}>
          <Stack spacing={2}>
            <Stack direction="row" justifyContent="center">
              <Typography variant="h6">Product Transaction History</Typography>
            </Stack>
            <Stack direction="row" justifyContent="space-between" spacing={2}>
              <TextField fullWidth id="asd" label="Product Serial" variant="outlined" inputRef={productHistRef} />
              <Button variant="contained" onClick={getHistory}>
                Refresh
              </Button>
            </Stack>
            <Divider />
            <Stack spacing={1} sx={{ overflowY: 'auto', maxHeight: 450 }}>
              {history.map((h) => {
                const hist = JSON.parse(h);
                return (
                  <Stack spacing={1} sx={{ p: 1, border: '5px solid #00000044', borderRadius: '8px' }}>
                    <Typography>{new Date(hist.timestamp * 1000).toLocaleString()}</Typography>
                    <Typography sx={{ overflowX: 'scroll', whiteSpace: 'nowrap' }}>
                      FROM: {hist.from_addr.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '')}
                    </Typography>
                    <Typography sx={{ overflowX: 'scroll', whiteSpace: 'nowrap' }}>
                      TO: {hist.to_addr.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '')}
                    </Typography>
                  </Stack>
                );
              })}
            </Stack>
          </Stack>
        </Grid>
        <Grid item xs={1} />
        <Grid item xs={5.5}>
          <Stack spacing={2}>
            <Stack spacing={2} sx={{ p: 2, border: '5px solid #00000044', borderRadius: '8px' }}>
              <Stack direction="row" justifyContent="center">
                <Typography variant="h6">Add New Product</Typography>
              </Stack>
              <TextField id="addpq3s" label="Seller Private Key" variant="outlined" inputRef={addProdPrivKeyRef} />
              <TextField id="addps" label="Product Serial" variant="outlined" inputRef={addProdRef} />
              <Button variant="contained" onClick={addProduct}>
                Add
              </Button>
            </Stack>
            <Stack spacing={2} sx={{ p: 2, border: '5px solid #00000044', borderRadius: '8px' }}>
              <Stack direction="row" justifyContent="center">
                <Typography variant="h6">Add New Transaction</Typography>
              </Stack>
              <TextField id="Product Serial" label="Product Serial" variant="outlined" inputRef={addTxProdRef} />
              <TextField id="Seller Private Key" label="Seller Private Key(demo purposes)" variant="outlined" inputRef={sellerRef} />
              <TextField id="Receiver Public Key" label="Receiver Public Key" variant="outlined" inputRef={recvRef} />
              <Button variant="contained" onClick={addTransaction}>
                Add
              </Button>
            </Stack>
          </Stack>
        </Grid>
      </Grid>
    </Container>
  );
}

export default App;
